<?php

namespace App\Http\Controllers;

use App\Http\Requests\LoginRequest;
use App\Http\Requests\RegisterRequest;
use App\Models\User;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Auth;
use Illuminate\Validation\ValidationException;
use Laravel\Socialite\Facades\Socialite;

class AuthController extends Controller
{
    /**
     * Handle an authentication attempt.
     *
     * @param  \App\Http\Requests\LoginRequest  $request
     * @return \Illuminate\Http\Response
     */
    public function authenticate(LoginRequest $request)
    {
        if (!Auth::attempt($request->validated())) {
            throw ValidationException::withMessages([
                'email' => 'The provided credentials do not match our records.',
            ]);
        }

        $request->session()->regenerate();
    }

    /**
     * Store new user in the database.
     * 
     * @param  \App\Http\Requests\RegisterRequest  $request
     * @return \Illuminate\Http\Response
     */
    public function register(RegisterRequest $request)
    {
        $data = $request->validated();
        $data['password'] = bcrypt($request->password);

        $user = User::create($data);
        return response()->json($user, 201);
    }

    public function googleCallback(Request $request)
    {
        $socialite = Socialite::driver('google')->redirectUrl($request->redirect_uri);

        $response = $socialite->getAccessTokenResponse($request->code);

        $googleUser = $socialite->userFromToken($response['access_token']);

        $user = User::where('google_id', $googleUser->getId())->first();

        if ($user) {
            $user->update([
                'google_token' => $googleUser->token,
                'google_refresh_token' => $googleUser->refreshToken,
            ]);
        } else {
            $user = User::create([
                'name' => $googleUser->getName(),
                'email' => $googleUser->getEmail(),
                'email_verified_at' => now(),
                'avatar' => $googleUser->getAvatar(),
                'google_id' => $googleUser->getId(),
                'google_token' => $googleUser->token,
                'google_refresh_token' => $googleUser->refreshToken,
                'tos_agreed' => true,
            ]);
        }

        return $user->createToken('google')->plainTextToken;
    }
}
