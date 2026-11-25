<?php

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Schema;

return new class extends Migration
{
    public function up(): void
    {
        Schema::create('customers', function (Blueprint $table) {
            $table->id();
            $table->string('email', 255);
            $table->string('full_name', 255);
            $table->timestamp('created_at')->useCurrent();
        });

        Schema::create('orders', function (Blueprint $table) {
            $table->id();
            $table->unsignedBigInteger('customer_id');
            $table->decimal('total', 10, 2);
            $table->timestamp('created_at')->useCurrent();

            $table->foreign('customer_id')->references('id')->on('customers');
        });

        DB::table('customers')->insert([
            ['id' => 1, 'email' => 'alice@example.com', 'full_name' => 'Alice Example'],
            ['id' => 2, 'email' => 'bob@example.com', 'full_name' => 'Bob Example'],
            ['id' => 3, 'email' => 'carol@example.com', 'full_name' => 'Carol Example'],
        ]);

        DB::table('orders')->insert([
            ['customer_id' => 1, 'total' => '19.99'],
            ['customer_id' => 1, 'total' => '5.50'],
            ['customer_id' => 2, 'total' => '120.00'],
            ['customer_id' => 3, 'total' => '42.42'],
        ]);
    }

    public function down(): void
    {
        Schema::dropIfExists('orders');
        Schema::dropIfExists('customers');
    }
};
