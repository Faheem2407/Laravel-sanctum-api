<?php

namespace App\Traits;

trait ApiResponse
{
    public function success($data=[], $message = null, $code = 200)
    {
        return response()->json([
            'status' => "success",
            'message' => $message,
            'data' => $data
        ], $code);
    }

    public function error($message = null, $code = 400)
    {
        return response()->json([
            'status' => "error",
            'message' => $message,
        ], $code);
    }
}
