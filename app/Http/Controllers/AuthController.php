<?php

namespace App\Http\Controllers;

use Illuminate\Http\Request;
use Illuminate\Support\Facades\Auth;
use App\Models\User;
use Illuminate\Support\Facades\Hash;

class AuthController extends Controller
{
    // რეგისტრაციის ფუნქცია
    public function register(Request $request)
    {
        $this->validateRegistration($request);

        $user = $this->createUser($request);

        return $this->generateTokenResponse($user);
    }

    // ავტორიზაციის ფუნქცია
    public function login(Request $request)
    {
        $this->validateLogin($request);

        if (!Auth::attempt($request->only('email', 'password'))) {
            return response()->json(['status' => 'error', 'message' => 'Invalid credentials'], 401);
        }

        $user = Auth::user();

        return $this->generateTokenResponse($user);
    }

    // მომხმარებლის დეტალების დაბრუნება
    public function user(Request $request)
    {
        return response()->json(['user' => $request->user()]);
    }

    // ლოგაუთი
    public function logout(Request $request)
    {
        $request->user()->currentAccessToken()->delete();

        return response()->json(['status' => 'success', 'message' => 'Logged out successfully']);
    }

    // ვალიდაციის მეთოდი რეგისტრაციისთვის
    private function validateRegistration(Request $request)
    {
        $request->validate([
            'name' => 'required|string|max:255',
            'email' => 'required|string|email|max:255|unique:users',
            'password' => 'required|string|min:8',
        ]);
    }

    // მომხმარებლის შექმნის მეთოდი
    private function createUser(Request $request): User
    {
        return User::create([
            'name' => $request->name,
            'email' => $request->email,
            'password' => Hash::make($request->password),
        ]);
    }

    // ვალიდაციის მეთოდი ავტორიზაციისთვის
    private function validateLogin(Request $request)
    {
        $request->validate([
            'email' => 'required|string|email',
            'password' => 'required|string',
        ]);
    }

    // ტოკენის გენერაციის და დაბრუნების მეთოდი
    private function generateTokenResponse(User $user)
    {
        $token = $user->createToken('auth_token')->plainTextToken;

        return response()->json([
            'status' => 'success',
            'user' => $user,
            'token' => $token,
        ]);
    }
}
