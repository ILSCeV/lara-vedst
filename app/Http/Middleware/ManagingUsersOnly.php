<?php

namespace Lara\Http\Middleware;

use Closure;
use Auth;
use Lara\Utilities;
use Session;

class ManagingUsersOnly
{
    /**
     * Handle an incoming request.
     *
     * @param  \Illuminate\Http\Request  $request
     * @param  \Closure  $next
     * @return mixed
     */
    public function handle($request, Closure $next)
    {
        if (!Auth::check()) {
            Utilities::error(trans('auth.notAuthenticated'));
            return Redirect('/');
        }

        if (!Auth::user()->is(['admin', 'marketing', 'clubleitung'])) {
            Utilities::error(trans('auth.missingPermissions'));
            return Redirect('/');
        }

        return $next($request);
    }
}
