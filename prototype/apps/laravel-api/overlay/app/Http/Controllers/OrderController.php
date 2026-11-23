<?php

namespace App\Http\Controllers;

use App\Models\Order;
use Illuminate\Http\JsonResponse;

class OrderController extends Controller
{
    public function index(): JsonResponse
    {
        return response()->json(
            Order::query()->orderBy('id')->get(['id', 'customer_id', 'total', 'created_at'])
        );
    }
}
