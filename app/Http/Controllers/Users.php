<?php

namespace App\Http\Controllers;

use Illuminate\Http\Request;
use App\Models\User;
use Illuminate\Support\Facades\Validator;
use Illuminate\Support\Facades\Auth;
use Illuminate\Support\Facades\Hash;

class Users extends Controller
{
    //


    public function register(Request $request)
    {
        $validator = Validator::make($request->all(), [
            'email' => 'nullable|email|max:64|unique:users',
            'password' => 'required|string|min:8',
            // add more validation cases if needed
            // https://laravel.com/docs/8.x/validation
        ]);

        if ($validator->fails()) {
            return response(['message' => 'Validation errors', 'errors' =>  $validator->errors(), 'status' => false], 422);
        }


        $input = $request->all();
        $input['password'] = Hash::make($input['password']);
        $user = User::create($input);

        /**Take note of this: Your user authentication access token is generated here **/
        $data['token'] =  $user->createToken('')->accessToken;

        return response(['data' => $data, 'message' => 'Account created successfully!', 'status' => true]);
    }



    /**
     * Log a User in
     *
     * @param  \Illuminate\Http\Request  $request
     * @return \Illuminate\Http\Response
     */
    public function signin(Request $request)
    {
        $validator = Validator::make($request->all(), [
            'email' => 'required|email|max:64|exists:users,email',
            'password' => 'required|string|min:8',
            // add more validation cases if ned
            // https://laravel.com/docs/8.x/valtion
        ]);

        if ($validator->fails()) {
            return response(['message' => 'Validation errors', 'errors' =>  $validator->errors(), 'status' => false], 422);
        }


        $credentials = $request->only('email', 'password');

        if (Auth::attempt($credentials)) {
            $authUser = Auth::user();
            $user = User::findOrFail($authUser->id);

            /**Take note of this: Your user authentication access token is generated here **/
            $data['token'] = $user->createToken('')->accessToken;
            // since we are not registering, we do not send the user data, since we should technically already have this data
            // (but you could do this if you wanted to)
            // $data['user_data'] = $user;

            return response(['data' => $data, 'message' => 'Account Logged In successfully!', 'status' => true]);
        } else {
            return response(['message' => 'Validation errors', 'errors' =>  ['password' => 'invalid password'], 'status' => false], 422);
        }
    }

    public function logout(Request $request)
    {
        if (Auth::check()) {
            $request->user()->token()->revoke();
            return response()->json(['success' => 'logout success'], 200);
        } else {
            return response()->json(['error' => 'something went wrong'], 500);
        }
    }
}
