<?php

namespace App\Http\Controllers;

use App\Models\Customer;
use Illuminate\Http\JsonResponse;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Log;

// Log lines carry only counts and ids, never customer fields (they go to the debug telemetry).
class CustomerController extends Controller
{
    public function index(): JsonResponse
    {
        $customers = Customer::query()->orderBy('id')->get(['id', 'email', 'full_name', 'created_at']);
        Log::info('Listed customers', ['count' => $customers->count()]);

        return response()->json($customers);
    }

    public function store(Request $request): JsonResponse
    {
        $data = $request->validate([
            'email' => ['required', 'string', 'email', 'max:255'],
            'full_name' => ['required', 'string', 'max:255'],
        ]);

        $customer = Customer::create($data);
        $customer->refresh(); // pick up created_at default from the DB
        Log::info('Created customer', ['customer_id' => $customer->id]);

        return response()->json($customer->only(['id', 'email', 'full_name', 'created_at']), 201);
    }
}
