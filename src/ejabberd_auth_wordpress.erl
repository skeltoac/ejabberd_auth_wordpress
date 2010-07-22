%%%-------------------------------------------------------------------
%%% File    : ejabberd_auth_wordpress.erl
%%% Author  : Andy Skelton <andy@automattic.com>
%%% Purpose : Uses a PHP API to authenticate users in WordPress.
%%% Created : 4 Feb 2009 by Andy Skelton <andy@automattic.com>
%%%-------------------------------------------------------------------

%% @doc Uses a PHP API to authenticate users in a WordPress database.

-module(ejabberd_auth_wordpress).

-include("ejabberd.hrl").

-export([start/1,stop/1,init/1,
	 set_password/3,
	 check_password/3,
	 check_password/5,
	 try_register/3,
	 dirty_get_registered_users/0,
	 get_vh_registered_users/1,
	 get_password/2,
	 get_password_s/2,
	 is_user_exists/2,
	 remove_user/2,
	 remove_user/3,
	 plain_password_required/0
	]).

-define(PHP_REQUIRE,
	"if ( !function_exists('ejabberd_check_password') ) {"
	" function ejabberd_check_password($user_login, $user_pass) {"
	"  $user = get_userdatabylogin($user_login);"
	"  if ( !$user || strcasecmp($user->user_login, $user_login) ) return false;"
	"  clean_user_cache($user->ID);"
	"  return !is_wp_error(wp_authenticate($user_login, $user_pass));"
	" }"
	"}"
	"if ( !function_exists('ejabberd_user_exists') ) {"
	" function ejabberd_user_exists($user_login) {"
	"  $user = get_userdatabylogin($user_login);"
	"  return ( $user && !strcasecmp($user->user_login, $user_login) );"
	" }"
	"}").

start(Host) ->
    php:start(),
    php:require_code(?PHP_REQUIRE),
    spawn(?MODULE, init, [Host]).

init(Host) ->
    register(gen_mod:get_module_proc(Host, auth_wordpress), self()),
    process_flag(trap_exit,true),
    loop().

stop(Host) ->
    gen_mod:get_module_proc(Host, auth_wordpress) ! stop.

plain_password_required() ->
    true.

check_password(User, _Server, Password) ->
    wp_check_password(User, Password).

check_password(User, Server, Password, _Digest, _DigestGen) ->
    check_password(User, Server, Password).

is_user_exists(User, _Server) ->
    wp_user_exists(User).

set_password(_User, _Server, _Password) ->
    {error, not_allowed}.
try_register(_,_,_) ->
    {error, not_allowed}.
dirty_get_registered_users() ->
    [].
get_vh_registered_users(_) ->
    [].
get_password(_,_) ->
    false.
get_password_s(_,_) ->    
    "".
remove_user(_,_) ->
    {error, not_allowed}.
remove_user(_,_,_) ->
    {error, not_allowed}.

wp_check_password(User, Password) ->
    case php:call("ejabberd_check_password", [User, Password]) of
	{ok, _, Bool, _, _} when is_boolean(Bool) ->
	    Bool;
	{exit, timeout} ->
	    wp_check_password(User, Password);
	_ ->
	    false
    end.

wp_user_exists(User) ->
    case php:call("ejabberd_user_exists", [User]) of
	{ok, _, Bool, _, _} when is_boolean(Bool) ->
	    Bool;
	{exit, timeout} ->
	    wp_user_exists(User);
	_ ->
	    false
    end.

loop() ->
    receive
	stop ->
	    ok;
	Exit when is_tuple(Exit), element(1, Exit) =:= 'EXIT' ->
	    ?CRITICAL_MSG("ejabberd_auth_wordpress received ~p~n", [Exit]),
	    exit(trapped_exit);
	Unknown ->
	    ?ERROR_MSG("ejabberd_auth_wordpress received unknown ~p~n", [Unknown]),
	    loop()
    end.
