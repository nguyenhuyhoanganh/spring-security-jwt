package com.security.javajwt.dto;

import lombok.Data;
import lombok.NoArgsConstructor;

import java.sql.Timestamp;

@Data
@NoArgsConstructor
public class ResponseDTO<D> {
    private Timestamp timestamp = new Timestamp(System.currentTimeMillis());

    private int status;

    private D data;

    private String path;

    public ResponseDTO(int status, String path) {
        this.status = status;
        this.path = path;
    }
}