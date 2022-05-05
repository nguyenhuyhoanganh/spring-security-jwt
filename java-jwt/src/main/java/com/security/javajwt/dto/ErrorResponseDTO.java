package com.security.javajwt.dto;

import lombok.Data;
import lombok.NoArgsConstructor;

import java.sql.Timestamp;

@Data
@NoArgsConstructor
public class ErrorResponseDTO {
    private Timestamp timestamp = new Timestamp(System.currentTimeMillis());

    private int status;

    private String error;

    private String path;

    public ErrorResponseDTO(int status, String error, String path) {
        this.status = status;
        this.error = error;
        this.path = path;
    }
}
