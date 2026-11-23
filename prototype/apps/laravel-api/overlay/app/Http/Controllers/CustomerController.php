<?php

namespace App\Http\Controllers;

use App\Models\Customer;
use Illuminate\Http\JsonResponse;
use Illuminate\Http\Request;

class CustomerController extends Controller
{
    public function index(): JsonResponse
    {
        return response()->json(
            Customer::query()->orderBy('id')->get(['id', 'email', 'full_name', 'created_at'])
        );
    }

    public function store(Request $request): JsonResponse
    {
        $data = $request->validate([
            'email' => ['required', 'string', 'email', 'max:255'],
            'full_name' => ['required', 'string', 'max:255'],
        ]);

        $customer = Customer::create($data);
        $customer->refresh(); // pick up created_at default from the DB

        return response()->json($customer->only(['id', 'email', 'full_name', 'created_at']), 201);
    }
}
