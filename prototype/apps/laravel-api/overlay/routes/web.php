<?php

use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Route;

Route::get('/health', function () {
    try {
        DB::select('select 1');
        return response()->json(['status' => 'ok', 'db' => 'ok']);
    } catch (\Throwable $e) {
        return response()->json(['status' => 'error', 'db' => 'down'], 503);
    }
});
