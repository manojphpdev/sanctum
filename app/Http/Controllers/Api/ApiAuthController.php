<?php
namespace App\Http\Controllers\Api;
use Validator;
use App\Models\User;
use Illuminate\Support\Facades\Hash;
use App\Http\Controllers\Controller;
use Illuminate\Http\Request;

class ApiAuthController extends Controller
{
    public function login(Request $request)
    {
        $validator = Validator::make($request->all() , 
        	['email' => 'required|string|email|max:255', 
        	'password' => 'required|string|min:6', ]);

        if ($validator->fails()){
            return response(['errors' => $validator->errors()
                ->all() ], 422);
        }

        $user = User::where('email', $request->email)->first();

        if ($user)
        {
            if (Hash::check($request->password, $user->password))
            {
                $token = $user->createToken($user->id.uniqid());
                return response()
                    ->json(['access_token' => $token->plainTextToken, 'token_type' => 'Bearer', ]);
            }
            else
            {
                $response = ["message" => "Password mismatch"];
                return response($response, 422);
            }
        }
        else
        {
            $response = ["message" => 'User does not exist'];
            return response($response, 422);
        }
    }

    public function register(Request $request)
    {
        $validatedData = $request->validate([
        	'name' => 'required|string|max:255', 
        	'email' => 'required|string|email|max:255|unique:users', 
        	'password' => 'required|string|min:6'
        ]);

        $user = User::create([
        	'name' => $validatedData['name'], 
        	'email' => $validatedData['email'], 
        	'password' => Hash::make($validatedData['password'])
        ]);

        $token = $user->createToken($user->id.uniqid())->plainTextToken;

        return response()
            ->json(['access_token' => $token, 'token_type' => 'Bearer', ]);
    }
}

