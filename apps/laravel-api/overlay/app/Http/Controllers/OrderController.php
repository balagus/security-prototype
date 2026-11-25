<?php

namespace App\Http\Controllers;

use App\Models\Order;
use Illuminate\Http\JsonResponse;
use Illuminate\Support\Facades\Log;

class OrderController extends Controller
{
    public function index(): JsonResponse
    {
        $orders = Order::query()->orderBy('id')->get(['id', 'customer_id', 'total', 'created_at']);
        Log::info('Listed orders', ['count' => $orders->count()]);

        return response()->json($orders);
    }
}
