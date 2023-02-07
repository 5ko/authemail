<?php if (!defined('PmWiki')) exit();
/**
  Email-based authentication and user management for PmWiki
  Written by (c) Petko Yotov 2017-2023   www.pmwiki.org/Petko

  This text is written for PmWiki; you can redistribute it and/or modify
  it under the terms of the GNU General Public License as published
  by the Free Software Foundation; either version 3 of the License, or
  (at your option) any later version. See pmwiki.php for full details
  and lack of warranty.
*/
$RecipeInfo['AuthEmail']['Version'] = '20230131';

if (@$_POST['authid']) AuthUserEmail();

include_once("$FarmD/scripts/author.php");
include_once("$FarmD/scripts/authuser.php");

$CurrentLocalTime = PSFT("@$TimeISOZFmt", $Now, null, 'GMT');

if($AuthId) {
  $Author = $AuthId;
  $AuthorId = $_SESSION['user_id'];
  $AuthorPage = "Profiles.$AuthorId";
  $AuthorLink = "[[~$AuthorId|{$_SESSION['real_name']}]]";
  $FmtPV['$AuthorId'] = '$_SESSION["user_id"]';
  $ROSPatterns = array(
    '/(?<!~)~~~~(?!~)/' => "$AuthorLink $CurrentLocalTime",
    '/(?<!~)~~~(?!~)/' => "$AuthorLink",
  );
  
//   xmps($AuthorLink);
}
else {
  $AuthorLink = "$Author (?)";
}

SDVA($AuthEmail, array(
  'CreateAccountForm' => '{$SiteGroup}.CreateAccountForm',
));

SDVA($HandleActions, array(
  'acreate'=>'HandleAEmail',
  'afpass'=>'HandleAEmail',
  'aWatch'=>'HandleAWatch',
  'aUnwatch'=>'HandleAWatch',
  'ausers'=>'HandleAUsers',
//   'watch'=>'HandleWatch',
));

$FmtPV['$WatchPage'] = 'FmtWatchPage($pn)';
$FmtPV['$UserName'] = 'FmtUserValues($group, $name, "real_name")';
$FmtPV['$UserEmail'] = 'FmtUserValues($group, $name, "email")';
$FmtPV['$UserGroups'] = 'FmtUserValues($group, $name, "usergroups")';
$FmtPV['$UserId'] = 'FmtUserValues($group, $name, "id")';
$EditFunctions[] = 'UpdateWatchlistFromDB';
$MarkupDirectiveFunctions['watchlist'] = 'FmtWatchlist';
$MarkupDirectiveFunctions['umtable'] = 'FmtUserManagement';

function FmtUserValues($group, $name, $row) {
  global $AuthorGroup;
  if($group != $AuthorGroup || !is_numeric($name)) return '';
  
  $x = db1('SELECT id, dec5ko(enc_name) AS real_name, email, usergroups
    FROM pmwiki_users where id = ? LIMIT 1', intval($name));
  
  return strval(@$x[$row]);
//   return Keep(pre_r($x));
}

function FmtUserManagement($pagename) {
  global $AuthorGroup, $TimeFmt;
  $x = dbak1('SELECT id, email, usergroups, accept_terms, 
    UNIX_TIMESTAMP(accept_terms) as stamp, 
    dec5ko(enc_name) AS real_name 
    FROM pmwiki_users WHERE id>0 ORDER BY real_name ASC');
  
  $table = [];
  $table[] = ['Name', 'Email', 'Permissions', 'Signed in'];
  foreach($x as $id=>$a) {
    $profileurl = PageVar("$AuthorGroup.$id", '$PageUrl');
    $rname = PHSC($a['real_name']);
    
    $n = "<input type='checkbox' name='user_ids[]' value='$id'> ";
    $n .= "<a class='wikilink profilelink' href='$profileurl'>$rname</a>";
    
    $email = "<a class='emaillink' href='mailto:{$a['email']}'>{$a['email']}</a>";
    
    $perms = $a['usergroups'];
    
    $time1 = PSFT("%FT%R", $a['stamp']);
    $time2 = substr(PSFT('%L', $a['stamp']), 1);
    
    $stamp = ".center <time datetime='$time2'>$time1</time>";
    
    $table[] = [$n, $email, $perms, $stamp];
  }
  return '<:block>' . Keep(MkTable($table));
}
function HandleAUsers($pagename) {
  
  $page = RetrieveAuthPage($pagename, 'admin', true, READPAGE_CURRENT);
  if(!$page) return Abort("?No permissions");
  
  global $MessagesFmt;
  
  if(isset($_POST['user_ids'])) {
    $perms = $_POST['perms'];
    if(!preg_match('/^@(admins|editors|readers|patrons|translators|clear)$/', $perms))
      return Abort('?Invalid permissions, please contact support.');
    
    $uids = array_map('intval', $_POST['user_ids']);
    $qms = implode(', ', array_fill(0, count($uids), '?'));
    
    if($perms == '@clear') $perms = '';
    
    array_unshift($uids, $perms);
    
    $query = "UPDATE pmwiki_users SET usergroups = ? WHERE id IN ( $qms )";
  
    $affected = dbz($query, $uids);
    $MessagesFmt[] = sprintf(XL("%d user(s) updated"), $affected);
  }
  
  HandleBrowse($pagename);
  
}


function UpdateWatchlistFromDB($pagename, $old, $new) {
  global $NotifyList, $IsPagePosted, $AuthorGroup;
  if (!$IsPagePosted) return;
  
  list($g, $n) = explode('.', $pagename);
  if($g == $AuthorGroup && is_numeric($n)) {
    $real_name = $new['title'];
    dbz('UPDATE IGNORE pmwiki_users SET enc_name = enc5ko( ? )
      WHERE id = ? LIMIT 1', $real_name, intval($n));
  }
  
  $x = dbac('SELECT pmwiki_users.email FROM `pmwiki_watchlists` 
    INNER JOIN pmwiki_users ON user_id = pmwiki_users.id 
    WHERE pagename = ? ', $pagename);
  if(!count($x)) return;
  $x = implode(',', $x);
  $notify = "notify=$x  name=$pagename";
  SDVA($NotifyList, array('ae'=>$notify));
}

function HandleAWatch($pagename, $auth = 'edit') {
  global $action, $AuthId, $EnablePost, $PageStartFmt, $PageEndFmt;
  $page = RetrieveAuthPage($pagename, $auth, true, READPAGE_CURRENT);
  if(!$page || !$AuthId) return  Abort('?No permissions');
  
  $list = GetWatchList(true);
  
  if($action == 'aUnwatch') {
    if(isset($_POST['unwatch_id'])) {
      xmps($_POST['unwatch_id']);
      dbz("DELETE FROM pmwiki_watchlists where id in ( ?? )",
        $_POST['unwatch_id'], 1);
    }
    else {
      dbz("DELETE FROM pmwiki_watchlists where user_id = ? and pagename = ? LIMIT 1",
        $_SESSION['user_id'], $pagename);
    }
  }
  elseif($action == 'aWatch') {
    dbz("INSERT IGNORE into pmwiki_watchlists (user_id, pagename) values (?, ?)",
      $_SESSION['user_id'], $pagename);
  }
  $list = GetWatchList(true);
  
  $_REQUEST['name'] = implode(',', array_values($list));
  
  $fmt = array($PageStartFmt, 'wiki:Site.Watchlist', $PageEndFmt);

  session_write_close();
  PrintFmt($pagename, $fmt);
}

function GetWatchList($update=false) {
  if($update || !isset($_SESSION['watchlist'])) {
    $_SESSION['watchlist'] = dbak1('SELECT id, pagename FROM pmwiki_watchlists 
      WHERE user_id = ? ORDER BY id DESC',  $_SESSION['user_id']);
  }
  return $_SESSION['watchlist'];
}

function FmtWatchlist($pagename) {
  global $TimeFmt, $TimeISOZFmt;
  
  $list = GetWatchList(true);
  $fliplist = array_flip($list);
  
  $names = implode(',', array_values($list));
  
  $list2 = $list3 = [];
  if($names) {
    $opt = [ 'name'=>$names ];
    $list2 = MakePageList($pagename, $opt);
  }
  foreach($list2 as $a) {
    extract($a);
    $id = $fliplist[$name];
    $title = PHSC(PageVar($name, '$Title'), ENT_QUOTES);
    $iso = PSFT($TimeISOZFmt, $time, null, 'GMT');
    $text = PSFT($TimeFmt, $time);
    $ltime = "<time datetime='$iso'>$text</time>";
    $fliplist[$name] = [ 'db_id'=>$id, 'title'=>$title, 'author'=>PHSC($a['author']), 
      'time'=>$a['time'], 'iso'=>$iso, 'ltime'=>$ltime, 
      'url'=>PageVar($name, '$PageUrl'), 'group'=>PageVar($name, '$Group')];
  }
  uasort($fliplist, 'SortWatchlist');
  
  $html = FmtPageName("<table class='simpletable sortable filterable'><thead><tr>
    <th>$[Section]</th>
    <th>$[Page]</th>
    <th>$[Modified]</th>
    <th>$[By]</th>
    <th>$[Unwatch]</th>
  </tr></thead><tbody>", $pagename);
  
  $unwatch = XL('Unwatch');
  foreach($fliplist as $pn=>$a) {
    $html .= "<tr>";
    $html .= "<td>{$a['group']}</td>";
    $html .= "<td><a class='wikilink' href='{$a['url']}'>{$a['title']}</a></td>";
    $html .= "<td class='center' data-sort='{$a['iso']}'>
      <a class='wikilink' href='{$a['url']}?action=diff'>{$a['ltime']}</a></td>";
    $html .= "<td>{$a['author']}</td>";
    $html .= "<td><a class='wikilink' href='{$a['url']}?action=aUnwatch'>$unwatch</a></td>";
    $html .= "</tr>";
  }
  $html .= '</tbody></table>';
  
  return PRR('<:block>'. Keep($html) . "\n");
}

function SortWatchlist($a, $b){ # recently modified first
  return $b['time'] - $a['time'];
}

function FmtWatchPage($pn) {
  global $AuthId;
  if(!$AuthId) return '';
  $list =  GetWatchList(true);
  
  $watched = array_search($pn, $list);
  
  $a = ($watched===false)? 'Watch': 'Unwatch';
  return "[[ $pn?action=a$a\"$[$a page]\"| ⭐ ]]";
}

function AuthUserEmail() {
  global $AuthUser, $AuthEmailAutoUserGroups, $AuthorId, $AuthorLink, $AuthorPage;
  SDVA($AuthEmailAutoUserGroups, array());
  
  $id = stripmagic(@$_POST['authid']);
  $_POST['authid'] = $id;
  
  $pw = stripmagic(@$_POST['authpw']);
  
  $p = db1('SELECT id, email, pass_hash, usergroups, dec5ko(enc_name) as real_name
    FROM pmwiki_users WHERE email = ? LIMIT 1', $id);
    
  if($p) {
    $salt = $p['pass_hash'];
    if(pmcrypt($pw, $salt) == $salt) {
      pm_session_start();
      $groups = preg_split('/[^-@\\w]+/', $p['usergroups'], -1, PREG_SPLIT_NO_EMPTY);
      foreach($groups as $g) {
        if(isset($AuthEmailAutoUserGroups[$g])) {
          $gg = preg_split('/[^-@\\w]+/', $AuthEmailAutoUserGroups[$g], -1, PREG_SPLIT_NO_EMPTY);
          $groups = array_merge($groups, $gg);
        }
      }
      $AuthUser[$p['email']] = array_unique($groups);
      $AuthUser[$p['email']][] = $p['pass_hash'];
      $_SESSION['real_name'] = $p['real_name'];
      $_SESSION['user_id'] = $AuthorId = $p['id'];
      $AuthorPage = "Profiles.$AuthorId";
      $AuthorLink = "[[~$AuthorId|+]]";
      dbz('UPDATE pmwiki_users SET accept_terms = CURRENT_TIMESTAMP WHERE id = ? LIMIT 1', $p['id']);
    }
  }
}


function HandleAEmail($pagename) {
  global $action, $MailFunction, $MessagesFmt, $AuthEmail, $Charset, $PageStartFmt, $PageEndFmt, $action, $InputValues, $WikiTitle, $FmtPV;
  
  pm_session_start();
  $phase = strval(@$_REQUEST['phase']);
  if($phase === '') { # initial form
    $InputValues['phase'] = 'typeemail';
  }
  elseif($phase == 'typeemail' && @$_POST['email']) {
    $email = stripmagic(trim($_POST["email"]));
    if (!filter_var($email, FILTER_VALIDATE_EMAIL)) {
      $MessagesFmt[] = XL("Invalid email address");
      $InputValues['phase'] = 'typeemail';
    }
    else {
      if($action == 'acreate' && dbc('SELECT id from pmwiki_users where email = ? limit 1', $email)) {
        $InputValues['phase'] = 'typeemail';
        $action = 'afpass';
        $MessagesFmt[] = XL("User already exists, you can already sign in. If you forgot your password, fill the form below.");
      }
      else {
        // send confirmation code to email
        $code = mt_rand(100000, 999999);
        $_SESSION['confirmcode'] = $code;
        $_SESSION['tmp_email'] = $email;
        
        $to = $email;
        $subj = $WikiTitle . ' ' . XL("Confirm email");
        $body =XL("Hello.\n\nHere is your confirmation code:\n   $code\n\nBest wishes,\n$WikiTitle team");
        $headers = "Content-Type: text/plain; charset=$Charset\r\n";
        
        $result = $MailFunction($to, $subj, $body, $headers);
        if($result) {
          $FmtPV['$EmailConfirmed'] = '"sent"';
          $InputValues['phase'] = 'confirmcode';
        }
        else {
          $FmtPV['$EmailConfirmed'] = '"error"';
          $InputValues['phase'] = '';
        }
      }
    }
  }
  elseif($phase == 'confirmcode') {
    if(@$_SESSION['confirmcode'] && intval(@$_POST['confirmcode']) === $_SESSION['confirmcode']) {
      $FmtPV['$EmailConfirmed'] = '"confirmed"';
      $InputValues['phase'] = 'selectpass';
      $InputValues['email'] = $_SESSION['confirmed_email'] = $_SESSION['tmp_email'];
    }
    else {
      $InputValues['email'] = $_SESSION['tmp_email'];
      $MessagesFmt[] = "Confirmation code not verified, please try again.";
      
      $FmtPV['$EmailConfirmed'] = '"sent"';
      $InputValues['phase'] = 'confirmcode';
    }
  
  }
  elseif($phase == 'selectpass' && $_SESSION['confirmed_email'] ) {
//     xmp($_POST);
    $pass = trim(strval(@$_POST['pass1']));
    $pass2 = trim(strval(@$_POST['pass2']));
    if(strlen($pass)<4) {
      $InputValues['email'] = $_SESSION['confirmed_email'];
      $MessagesFmt[] = XL("Please select a longer password.");
      $FmtPV['$EmailConfirmed'] = '"confirmed"';
      $InputValues['phase'] = 'selectpass';
    }
    elseif($pass != $pass2) {
      $InputValues['email'] = $_SESSION['confirmed_email'];
      $MessagesFmt[] = XL("Please type the same password twice.");
      $FmtPV['$EmailConfirmed'] = '"confirmed"';
      $InputValues['phase'] = 'selectpass';
    }
    else {
      $email = $_SESSION['confirmed_email'];
      $cpass = pmcrypt($pass);
      $id = dbc('SELECT id from pmwiki_users where email = ? limit 1', $email);
      if($id) { // existing account, change password
        $q = 'UPDATE pmwiki_users set pass_hash = ? where id = ? limit 1;';
        dbz($q, $cpass, $id);
        
        $MessagesFmt[] = XL("Password changed, you can now sign in.");
        $FmtPV['$EmailConfirmed'] = '"passchanged"';
      }
      else { // CREATE USER
        $email = $_SESSION['confirmed_email'];
        global $AuthEmailAutoCreateUserGroups, $AuthorGroup, $ChangeSummary, $Now;
        $ug = [];
        foreach((array)@$AuthEmailAutoCreateUserGroups as $pat=>$perms) {
          if($pat && $perms && preg_match($pat, $email)) $ug[] = $perms;
        }
        $ug = implode(' ', $ug);
        $q = 'INSERT into pmwiki_users (email, usergroups, enc_name, pass_hash) 
          values ( ?, ?, enc5ko( ? ), ? );';
        $name = trim(strval(@$_POST['realname']));
        if(!$name) $name = $email;
        
        dbz($q, $email, $ug, $name, $cpass);
        
        $user_id = dbc('select id from pmwiki_users where email = ? limit 1', $email);
        $userpn = "$AuthorGroup.$user_id";
        
        $page = $new = ReadPage($userpn);
        $ChangeSummary = $new['csum'] = $new["csum:$Now"] = 'Account created';
        $new['title'] = $name;
        $new['text'] = "(:allegro:)(:allegroend:)\n(:Status:draft:)\n(:title $name:)\n";
        $new['passwdedit'] = "id:$email";
        UpdatePage($userpn, $page, $new);
        
        $MessagesFmt[] = XL("User {$_SESSION['confirmed_email']} created, you can now sign in.");
        $FmtPV['$EmailConfirmed'] = '"created"';
      }
      
      
      unset($_SESSION['confirmcode'], $_SESSION['confirmed_email'], 
        $_SESSION['tmp_email']);
    
    }
  }
  else {
    $MessagesFmt[] = 'This shouldn\'t happen.';
//     xmp([$_SESSION, $_POST, $phase], 1);
  }
  
  DisableSkinParts('header footer left right actions title');
  $fmt = array($PageStartFmt, "page:{$AuthEmail['CreateAccountForm']}", $PageEndFmt);
  
  PrintFmt($pagename, $fmt);
}
