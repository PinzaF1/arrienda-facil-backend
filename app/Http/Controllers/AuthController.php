<?php

namespace App\Http\Controllers;

use App\Models\User;
use Illuminate\Http\JsonResponse;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Auth;
use Illuminate\Validation\ValidationException;

class AuthController extends Controller
{
    public function register(Request $request): JsonResponse
    {
        $validatedData = $request->validate([
            'name' => ['required', 'string', 'max:255'],
            'email' => ['required', 'string', 'email', 'max:255', 'unique:users,email'],
            'password' => ['required', 'string', 'min:6', 'confirmed'],
        ]);

        $user = User::create([
            'name' => $validatedData['name'],
            'email' => $validatedData['email'],
            'password' => $validatedData['password'],
        ]);

        $token = Auth::guard('api')->login($user);

        return $this->tokenResponse($token, $user, 201);
    }

    public function login(Request $request): JsonResponse
    {
        $credentials = $request->validate([
            'email' => ['required', 'email'],
            'password' => ['required', 'string'],
        ]);

        // Login only authenticates existing users; it must never create records.
        if (! $token = Auth::guard('api')->attempt($credentials)) {
            throw ValidationException::withMessages([
                'email' => ['Credenciales inválidas.'],
            ]);
        }

        /** @var User $user */
        $user = Auth::guard('api')->user();

        return $this->tokenResponse($token, $user);
    }

    public function me(): JsonResponse
    {
        /** @var User $user */
        $user = Auth::guard('api')->user();

        return response()->json($user);
    }

    public function logout(): JsonResponse
    {
        Auth::guard('api')->logout();

        return response()->json([
            'message' => 'Sesión cerrada correctamente.',
        ]);
    }

    public function refresh(): JsonResponse
    {
        $token = Auth::guard('api')->refresh();

        /** @var User $user */
        $user = Auth::guard('api')->user();

        return $this->tokenResponse($token, $user);
    }

    private function tokenResponse(string $token, User $user, int $statusCode = 200): JsonResponse
    {
        return response()->json([
            'access_token' => $token,
            'token_type' => 'bearer',
            'user' => $user,
        ], $statusCode);
    }
}
