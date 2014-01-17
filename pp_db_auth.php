<?php
/*
	Plugin Name: Wordpress Multisite External Database Authentication
	Description: Used to externally authenticate WP users with an existing user database. Uses PDO for database connections and support custom hashing functions.
	Version: 2.0
	Author: Anthony Kuske
	Author URI: http://www.anthonykuske.com
		
	Based on original plugin: External Database Authentication Reloaded by Joshua Parker
	Original Plugin URI: http://www.7mediaws.org/extend/plugins/external-db-auth-reloaded/
	Original Author URI: http://www.joshparker.us/
	Original Author: Charlene Barina
	Original Author URI: http://www.ploofle.com

    Copyright 2007  Charlene Barina  (email : cbarina@u.washington.edu)

    This program is free software; you can redistribute it and/or modify
    it  under the terms of the GNU General Public License as published by
    the Free Software Foundation; either version 2 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program; if not, write to the Free Software
    Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
*/

function pp_db_auth_init() {
	add_site_option('pp_db_pdo_string', '');
	add_site_option('pp_db_table',"");
	add_site_option('pp_db_namefield',"");
	add_site_option('pp_db_pwfield',"");
	add_site_option('pp_db_first_name',"");
	add_site_option('pp_db_last_name',"");
	add_site_option('pp_db_user_url',"");
	add_site_option('pp_db_user_email',"");
	add_site_option('pp_db_description',"");
	add_site_option('pp_db_aim',"");
	add_site_option('pp_db_yim',"");
	add_site_option('pp_db_jabber',"");
	add_site_option('pp_db_enc',"");
	add_site_option('pp_db_other_enc',"");
	add_site_option('pp_db_error_msg',"");
	add_site_option('pp_db_role_bool','');
	add_site_option('pp_db_role','');
	add_site_option('pp_db_role_value','');
	add_site_option('pp_db_site_url','');
}

//Add page for network admin menu
function pp_db_auth_add_menu() {
	add_submenu_page('settings.php', "External DB settings", "External DB settings", 'manage_options', 'pp_db_auth_settings', "pp_db_auth_display_options");
}

//actual configuration screen
function pp_db_auth_display_options() { 

	//Save changes
	if (!empty($_POST)) {
		update_site_option('pp_db_pdo_string', $_POST['pp_db_pdo_string']);
		update_site_option('pp_db_table', $_POST['pp_db_table']);
		update_site_option('pp_db_namefield', $_POST['pp_db_namefield']);
		update_site_option('pp_db_pwfield', $_POST['pp_db_pwfield']);
		update_site_option('pp_db_first_name', $_POST['pp_db_first_name']);
		update_site_option('pp_db_last_name', $_POST['pp_db_last_name']);
		update_site_option('pp_db_user_url', $_POST['pp_db_user_url']);
		update_site_option('pp_db_user_email', $_POST['pp_db_user_email']);
		update_site_option('pp_db_description', $_POST['pp_db_description']);
		update_site_option('pp_db_aim', $_POST['pp_db_aim']);
		update_site_option('pp_db_yim', $_POST['pp_db_yim']);
		update_site_option('pp_db_jabber', $_POST['pp_db_jabber']);
		update_site_option('pp_db_enc', $_POST['pp_db_enc']);
		update_site_option('pp_db_other_enc', stripslashes($_POST['pp_db_other_enc']));
		update_site_option('pp_db_error_msg', $_POST['pp_db_error_msg']);
		update_site_option('pp_db_role_bool', $_POST['pp_db_role_bool']);
		update_site_option('pp_db_role', $_POST['pp_db_role']);
		update_site_option('pp_db_role_value', $_POST['pp_db_role_value']);
		update_site_option('pp_db_site_url', $_POST['pp_db_site_url']);
	}

	?>
	<div class="wrap">
	<h2><?php _e( 'External Database Authentication Settings' ); ?></h2>        
	<form method="post" action="settings.php?page=pp_db_auth_settings">
	<?php settings_fields('pp_db_auth'); ?>
        <h3><?php _e( 'External Database Settings' ); ?></h3>
          <strong><?php _e( 'Make sure your WP admin account exists in the external db prior to saving these settings.'); ?></strong>
        <table class="form-table">
             
        <tr valign="top">
            <th scope="row"><label><?php _e( 'PDO Connection String' ); ?></label></th>
				<td><input type="text" name="pp_db_pdo_string" value="<?php echo get_site_option('pp_db_pdo_string'); ?>" /> </td>
				<td><span class="description"><strong style="color:red;"><?php _e( 'required' ); ?></strong>; <a href="http://www.electrictoolbox.com/php-pdo-dsn-connection-string/" target="_blank">See here for examples</a></span> </td>
        </tr>
		<tr valign="top">
            <th scope="row"><label><?php _e( 'Users table' ); ?></label></th>
				<td><input type="text" name="pp_db_table" value="<?php echo get_site_option('pp_db_table'); ?>" /></td>
				<td><span class="description"><strong style="color:red;"><?php _e( 'required' ); ?></strong></span></td>
        </tr>
        </table>
        

        <table class="form-table">
        <tr valign="top">
            <th scope="row"><label><?php _e( 'Username field name in external DB' ); ?></label></th>
				<td><input type="text" name="pp_db_namefield" value="<?php echo get_site_option('pp_db_namefield'); ?>" /></td>
				<td><span class="description"><strong style="color:red;"><?php _e( 'required' ); ?></strong></span></td>
        </tr>
        <tr valign="top">
            <th scope="row"><label><?php _e( 'Password field name in external DB' ); ?></label></th>
				<td><input type="text" name="pp_db_pwfield" value="<?php echo get_site_option('pp_db_pwfield'); ?>" /></td>
				<td><span class="description"><strong style="color:red;"><?php _e( 'required' ); ?></strong></span><td>
        </tr>
        <tr valign="top">
            <th scope="row"><?php _e( 'Password encryption method' ); ?></th>
                <td><select name="pp_db_enc">
                	<?php
                		$encType = get_site_option('pp_db_enc');
                	?>
                	<option <?php if ($encType == 'SHA1') { echo 'selected="selected"'; }?>>SHA1</option>
                	<option <?php if ($encType == 'MD5') { echo 'selected="selected"'; }?>>MD5</option>
                	<option <?php if ($encType == 'Custom') { echo 'selected="selected"'; }?>>Custom</option>
				</select></td>
			<td><span class="description"><strong style="color:red;"><?php _e( 'required' ); ?></strong> <?php _e( '(Selecting "Other" requires you to enter PHP code below!)' ); ?></td>            
        </tr>
        <tr valign="top">
            <th scope="row"><label><?php _e( 'Custom password checking code' ); ?></label></th>
				<td><textarea type="text" name="pp_db_other_enc" cols="50" rows="5"><?php echo get_site_option('pp_db_other_enc'); ?></textarea>
				<td><span class="description"><?php _e( 'The PHP code you write here will be used if you pick "Other" as the password encryption method. In this code, return true or false if the user\'s password is correct. You are given the variables $dbPassword which is the stored password, and $username and $password which is what the user entered. Note: this only runs if the username exists in the database. If not, it will exit before it gets to this code.<br/>e.g. if the password was cleartext:<br/>
return $password == $dbPassword;' ); ?></td>
    	</tr>
    	<? /*
    	//Not implemented
		<tr valign="top">
            <th scope="row"><label><?php _e( 'Role check' ); ?></label></th>
			<td><input type="text" name="pp_db_role" value="<?php echo get_site_option('pp_db_role'); ?>" />
				<br />
				<select name="pp_db_role_bool">
                <?php 
                    switch(get_site_option('pp_db_role_bool')) {
                    case "is" :
                        echo '<option selected="selected">is</option><option>greater than</option><option>less than</option>';
                        break;
                    case "greater than" :
                        echo '<option>is</option><option selected="selected">greater than</option><option>less than</option>';
                        break;                
                    case "less than" :
                        echo '<option>is</option><option>greater than</option><option selected="selected">less than</option>';
                        break;                                        
                    default :
                        echo '<option selected="selected">is</option><option>greater than</option><option>less than</option>';
                        break;
                    }
                ?>
				</select><br />
				<input type="text" name="pp_db_role_value" value="<?php echo get_site_option('pp_db_role_value'); ?>" /></td>
				<td><span class="description"><?php _e( 'Use this if you have certain user role ids in your external database to further restrict allowed logins.  If unused, leave fields blank.' ); ?></span></td>
        </tr> */ ?>
        </table>
        
        <h3><?php _e( 'External Database Source Fields' ); ?></h3>
        <p>Enter these optional field names in the external db and the values from them will be used for the user's Wordpress account that gets created.</p>
        
        <table class="form-table">
        <tr valign="top">
            <th scope="row"><label><?php _e( 'First name' ); ?></label></th>
			<td><input type="text" name="pp_db_first_name" value="<?php echo get_site_option('pp_db_first_name'); ?>" /></td>
        </tr>
        <tr valign="top">
            <th scope="row"><label><?php _e( 'Last name' ); ?></label></th>
			<td><input type="text" name="pp_db_last_name" value="<?php echo get_site_option('pp_db_last_name'); ?>" /></td>
        </tr>
        <tr valign="top">
            <th scope="row"><label><?php _e( 'Homepage' ); ?></label></th>
			<td><input type="text" name="pp_db_user_url" value="<?php echo get_site_option('pp_db_user_url'); ?>" /></td>
        </tr>
        <tr valign="top">
            <th scope="row"><label><?php _e( 'Email' ); ?></label></th>
			<td><input type="text" name="pp_db_user_email" value="<?php echo get_site_option('pp_db_user_email'); ?>" /></td>
        </tr>
        <tr valign="top">
            <th scope="row"><label><?php _e( 'Bio/description' ); ?></label></th>
			<td><input type="text" name="pp_db_description" value="<?php echo get_site_option('pp_db_description'); ?>" /></td>
        </tr>
        <tr valign="top">
            <th scope="row"><label><?php _e( 'AIM screen name' ); ?></label></th>
			<td><input type="text" name="pp_db_aim" value="<?php echo get_site_option('pp_db_aim'); ?>" /></td>
        </tr>
        <tr valign="top">
            <th scope="row"><label><?php _e( 'YIM screen name' ); ?></label></th>
			<td><input type="text" name="pp_db_yim" value="<?php echo get_site_option('pp_db_yim'); ?>" /></td>
        </tr>
        <tr valign="top">
            <th scope="row"><label><?php _e( 'JABBER screen name' ); ?></label></th>
			<td><input type="text" name="pp_db_jabber" value="<?php echo get_site_option('pp_db_jabber'); ?>" /></td>
        </tr>
        </table>
        <h3><?php _e( 'Other' ); ?></h3>
        <table class="form-table">
    	<tr valign="top">
        	<th scope="row"><label><?php _e( 'External Site URL' ); ?></label></th>
			<td><input type="text" name="pp_db_site_url" value="<?php echo get_site_option('pp_db_site_url'); ?>" /></td>
			<td><span class="description"><strong style="color:red;"><?php _e( 'required' ); ?></strong></span></td>
        </tr>
        <tr valign="top">
                <th scope="row"><?php _e( 'Custom login message' ); ?></th>
                <td><textarea name="pp_db_error_msg" cols=40 rows=4><?php echo htmlspecialchars(get_site_option('pp_db_error_msg'));?></textarea></td>
                <td><span class="description"><?php _e( 'Shows up in login box, e.g., to tell them where to get an account. You can use HTML in this text.' ); ?></td>
        </tr>        
    </table>
	
	<p class="submit">
	<input type="submit" name="Submit" value="Save changes" />
	</p>
	</form>
	</div>
<?php
}

function pp_check_password_custom($code, $username, $password, $dbPassword) {
	return eval($code);
}

//actual meat of plugin - essentially, you're setting $username and $password to pass on to the system.
//You check from your external system and insert/update users into the WP system just before WP actually
//authenticates with its own database.
function pp_db_auth_check_login($username,$password) {
	require_once('./wp-includes/user.php');
	require_once('./wp-includes/pluggable.php');
	
    $pp_hasher = new PasswordHash(8, FALSE);
    
    //Connect to external database
	$db = new PDO(get_site_option('pp_db_pdo_string'));
	$db->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
	$db->setAttribute(PDO::ATTR_DEFAULT_FETCH_MODE, PDO::FETCH_ASSOC);
    
	//prepare the db for unicode queries
	//to pick up umlauts, non-latin text, etc., without choking	
	#$utfquery = "SET NAMES 'utf8'";
	#$resultutf = db_functions($driver,"query",$resource,$utfquery);  

	//Load the user's info from the DB
	$query = 'SELECT * FROM '.get_site_option('pp_db_table').' WHERE '.get_site_option('pp_db_namefield').' = ? LIMIT 1';
	$query = $db->prepare($query);
	$query->execute(array($username));
	$externalUser = $query->fetch();
	
	//Done with the database now
	$db = null;
	
	//If no user was found
	if (empty($externalUser)) {
		global $pp_error;
		$pp_error = "notindb";
		$username = NULL;
		return;
	}

	//Check the password hash
	
	$dbPassword = $externalUser[get_site_option('pp_db_pwfield')];

	//do the password hash for comparing
	switch(get_site_option('pp_db_enc')) {
		case "SHA1" :
			$passwordCorrect = sha1($password) == $dbPassword;
			break;
			
		case "MD5" :
			$passwordCorrect = md5($password) == $dbPassword;
			break;
			
        case "Custom" :             //right now defaulting to plaintext.  People can change code here for their own special hash
        	$passwordCorrect = pp_check_password_custom(get_site_option('pp_db_other_enc'), $username, $password, $dbPassword);
            break;
	}
	    
	if ($passwordCorrect !== true) {
		global $pp_error;
		$pp_error = "wrongpw";				
		$username = NULL;
		return;	
	}
   
	//Set the mapping of fields from the external db to the wordpress db
	$sqlfields['first_name'] = get_option('pp_db_first_name');
	$sqlfields['last_name'] = get_option('pp_db_last_name');
	$sqlfields['user_url'] = get_option('pp_db_user_url');
	$sqlfields['user_email'] = get_option('pp_db_user_email');
	$sqlfields['description'] = get_option('pp_db_description');
	$sqlfields['aim'] = get_option('pp_db_aim');
	$sqlfields['yim'] = get_option('pp_db_yim');
	$sqlfields['jabber'] = get_option('pp_db_jabber');        
	$sqlfields['pp_db_role'] = get_option('pp_db_role');
   
   //Insert or update the user in wordpress
	$wordpressUser = array();
	$wordpressUser['user_login'] = $username;
	$wordpressUser['user_pass'] = $password;
	$wordpressUser['first_name'] = !empty($sqlfields['first_name']) ? $externalUser[$sqlfields['first_name']] : '';
	$wordpressUser['last_name'] = !empty($sqlfields['last_name']) ? $externalUser[$sqlfields['last_name']] : '';        
	$wordpressUser['user_url'] = !empty($sqlfields['user_url']) ? $externalUser[$sqlfields['user_url']] : '';
	$wordpressUser['user_email'] = !empty($sqlfields['user_email']) ? $externalUser[$sqlfields['user_email']] : '';
	$wordpressUser['description'] = !empty($sqlfields['user_email']) ? $externalUser[$sqlfields['description']] : '';
	$wordpressUser['aim'] = !empty($sqlfields['aim']) ? $externalUser[$sqlfields['aim']] : '';
	$wordpressUser['yim'] = !empty($sqlfields['yim']) ? $externalUser[$sqlfields['yim']] : '';
	$wordpressUser['jabber'] = !empty($sqlfields['jabber']) ? $externalUser[$sqlfields['jabber']] : '';
	
	if (!empty($sqlfields['first_name']) || !empty($sqlfields['last_name'])) {
		$wordpressUser['display_name'] = $externalUser[$sqlfields['first_name']]." ".$externalUser[$sqlfields['last_name']];            
	}
		
	if (empty($wordpressUser['display_name'])) {
		$wordpressUser['display_name'] = $username;
	}
		
	if ($id = username_exists($username)) {
		//If user is already in wordpress, update
		$wordpressUser['ID'] = $id;
		 wp_update_user($wordpressUser);
	} else {
		//Otherwise create a new user		
		wp_insert_user($wordpressUser);
	}
}


//gives warning for login - where to get "source" login
function pp_db_auth_warning() {
   echo "<p class=\"message\">".get_site_option('pp_db_error_msg')."</p>";
}

function pp_db_errors() {
	global $error;
	global $pp_error;
	if ($pp_error == "notindb")
		return "<strong>ERROR:</strong> Username not found.";
	else if ($pp_error == "wrongrole")
		return "<strong>ERROR:</strong> You don't have permissions to log in.";
	else if ($pp_error == "wrongpw")
		return "<strong>ERROR:</strong> Invalid password.";
	else
		return $error;
}

//hopefully grays stuff out.
function pp_db_warning() {
	echo '<strong style="color:red;">Any changes made below WILL NOT be preserved when you login again. You have to change your personal information per instructions found @ <a href="' . get_site_option('pp_db_site_url') . '">login box</a>.</strong>'; 
}

//disables the (useless) password reset option in WP when this plugin is enabled.
function pp_db_show_password_fields() {
	return 0;
}


/*
 * Disable functions.  Idea taken from http auth plugin.
 */
function disable_function_register() {	
	$errors = new WP_Error();
	$errors->add('registerdisabled', __('User registration is not available from this site, so you can\'t create an account or retrieve your password from here. See the message above.'));
	?></form><br /><div id="login_error"><?php _e( 'User registration is not available from this site, so you can\'t create an account or retrieve your password from here. See the message above.' ); ?></div>
		<p id="backtoblog"><a href="<?php bloginfo('url'); ?>/" title="<?php _e('Are you lost?') ?>"><?php printf(__('&larr; Back to %s'), get_bloginfo('title', 'display' )); ?></a></p>
	<?php
	exit();
}

function disable_function() {	
	$errors = new WP_Error();
	$errors->add('registerdisabled', __('User registration is not available from this site, so you can\'t create an account or retrieve your password from here. See the message above.'));
	login_header(__('Log In'), '', $errors);
	?>
	<p id="backtoblog"><a href="<?php bloginfo('url'); ?>/" title="<?php _e('Are you lost?') ?>"><?php printf(__('&larr; Back to %s'), get_bloginfo('title', 'display' )); ?></a></p>
	<?php
	exit();
}


add_action('admin_init', 'pp_db_auth_init' );
add_action('network_admin_menu', 'pp_db_auth_add_menu');
add_action('wp_authenticate', 'pp_db_auth_check_login', 1, 2 );
add_action('lost_password', 'disable_function');
//add_action('user_register', 'disable_function');
add_action('register_form', 'disable_function_register');
add_action('retrieve_password', 'disable_function');
add_action('password_reset', 'disable_function');
add_action('profile_personal_options','pp_db_warning');
add_filter('login_errors','pp_db_errors');
add_filter('show_password_fields','pp_db_show_password_fields');
add_filter('login_message','pp_db_auth_warning');

register_activation_hook( __FILE__, 'pp_db_auth_activate' );
?>