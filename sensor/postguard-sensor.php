<?php

/*
Plugin Name: PostGuard Sensor
Version: 0.2
*/

if (!defined('ABSPATH')) exit;

function pg_hmac_signature($timestamp, $body, $secret){

    $message= $timestamp . "." . $body;
    return hash_hmac('sha256', $message, $secret);

}
//This function builds and signs sensor events before sending them.
function pg_send_event($event_type, $meta = array()){

    $url    = getenv('PG_API_URL') ?: 'http://api:8000/api/events/ingest';
    $key_id = getenv('PG_API_KEY_ID')?: '';
    $secret = getenv('PG_API_KEY_SECRET')?:'';
    $payload = array(
        "source"=>"wp_sensor",
        "event_type"=> $event_type,
        "occurred_at" => gmdate('c'),
        "actor_user_id"=> is_user_logged_in() ? (string)get_current_user_id():null,
        "actor_user_name" => is_user_logged_in()? wp_get_current_user()->user_login : null,
        "path" => null,
        "directory"=> null,
        "meta"=> $meta
    );

    $body = wp_json_encode($payload);
    $ts = time();
    $sig = pg_hmac_signature($ts, $body, $secret);
    $args = array(

        'method'=> 'POST',
        'timeout'=> 5,
        'headers' => array(
            'Content-Type' => 'application/json',
            'X-PG-API-KEY' => $key_id,
            'X-PG-TIMESTAMP' => (string)$ts,
            'X-PG-SIGNATURE' => $sig,

        ),
        'body'=>$body
    
    );
    wp_remote_post($url, $args);

}
// Register the WordPress actions monitored by the sensor.
add_action('wp_login', function ($user_login, $user){
    pg_send_event('login', array("user_login"=> $user_login, "target_user_id"=>(string) $user->ID));
},10,2);

add_action('profile_update', function($user_id, $old_user_data){
    pg_send_event('profile_update', array("target_user_id" =>(string)$user_id));
},10,2);

add_action('save_post', function($post_id, $post, $updated){
    if (wp_is_post_revision($post_id)||(defined('DOING_AUTOSAVE') && DOING_AUTOSAVE)) {
        return;
    }

    pg_send_event('post_edit', array( 
        "post_id" =>(string) $post_id,
        "post_type" => $post->post_type,
        "post_status"=> $post->post_status,
        "updated" => (bool) $updated        
    ));

}, 10,3);

add_action('delete_post', function($post_id, $post){
    pg_send_event('post_delete', array("post_id" =>(string)$post_id, "post_type" => get_post_type($post_id)));
},10,2);


add_action('add_attachment', function($post_id){
    $file_path =get_attached_file($post_id);
    pg_send_event('upload', array("attachment_id" =>(string)$post_id, "file_path" => $file_path ? $file_path : null));
},10,1);

add_action('delete_attachment', function($post_id){
    $file_path =get_attached_file($post_id);
    pg_send_event('delete_attachment', array("attachment_id" =>(string)$post_id, "file_path" => $file_path ? $file_path : null));
},10,1);

add_action('user_register', function($user_id){
    pg_send_event('user_register', array("target_user_id" =>(string)$user_id));
},10,1);

add_action('delete_user', function($user_id){
    pg_send_event('user_delete', array("target_user_id" =>(string)$user_id));
},10,1);

add_action('set_user_role', function($user_id, $role, $old_roles){
    pg_send_event('role_change', array("target_user_id" =>(string)$user_id, "new_role"=>$role,"old_roles" => $old_roles));
},10,3);

add_action('activated_plugin', function($plugin){
    $plugin_path =trailingslashit(WP_PLUGIN_DIR) . ltrim((string)$plugin, '/\\');
    pg_send_event('plugin_activated', array("plugin" =>(string)$plugin,"path"=>$plugin_path,"file_path" => $plugin_path));
},10,1);

add_action('deactivated_plugin', function($plugin){
    $plugin_path = trailingslashit(WP_PLUGIN_DIR) . ltrim((string)$plugin, '/\\');
    pg_send_event('plugin_deactivated', array("plugin" =>(string)$plugin,"path" => $plugin_path, "file_path"=>$plugin_path));
},10,1);

add_action('switch_theme', function($new_name, $new_theme, $old_theme){
    $theme_slug =$new_theme instanceof WP_Theme ? $new_theme->get_stylesheet() : sanitize_title($new_name);
    $theme_path = trailingslashit(get_theme_root()) . $theme_slug;


    pg_send_event('theme_switched',array(
        "new_theme" => $new_name,
        "new_theme_slug" => $theme_slug,
        "old_theme" => $old_theme ? $old_theme->get('Name') : null,
        "path" => $theme_path,
        "file_path" => $theme_path
    ));

},10,3);


add_action('upgrader_process_complete', function($upgrader, $hook_extra) {
    $meta = array("hook_extra" => $hook_extra);

    if(!empty($hook_extra['plugin'])){
        $plugin_path = trailingslashit(WP_PLUGIN_DIR) . ltrim((string)$hook_extra['plugin'], '/\\');
        $meta["path"] = $plugin_path;
        $meta["file_path"] = $plugin_path;
    }

    if(!empty($hook_extra['theme'])){
        $theme_slug =(string)$hook_extra['theme'];
        $theme_path = trailingslashit(get_theme_root()) . $theme_slug;
        $meta["path"] = $theme_path;
        $meta["file_path"] = $theme_path;
    }

    pg_send_event('upgrader_completed', $meta);
    
},10,2);
