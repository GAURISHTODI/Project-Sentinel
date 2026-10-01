package com.sentinel.shop.web;

import com.sentinel.shop.ShopProperties;
import java.io.PrintWriter;
import java.io.StringWriter;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.UUID;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.http.converter.HttpMessageNotReadableException;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;
import org.springframework.web.method.annotation.MethodArgumentTypeMismatchException;
import org.springframework.web.servlet.resource.NoResourceFoundException;

/**
 * v1 VULNERABLE (F-14): unhandled errors return the exception and a stack trace to the client.
 * v2 FIXED: a generic message plus a correlation id; the detail stays in the server log.
 */
@RestControllerAdvice
public class GlobalErrorHandler {
    private static final Logger log = LoggerFactory.getLogger(GlobalErrorHandler.class);
    private final ShopProperties props;

    public GlobalErrorHandler(ShopProperties props) {
        this.props = props;
    }

    @ExceptionHandler({HttpMessageNotReadableException.class, MethodArgumentTypeMismatchException.class})
    public ResponseEntity<Map<String, Object>> badRequest(Exception e) {
        Map<String, Object> body = new LinkedHashMap<>();
        body.put("error", "bad request");
        if (!props.secure()) {
            body.put("detail", e.toString());
        }
        return ResponseEntity.status(HttpStatus.BAD_REQUEST).body(body);
    }

    /** Unknown routes are a plain 404 (never a 500) in both versions. */
    @ExceptionHandler(NoResourceFoundException.class)
    public ResponseEntity<Map<String, Object>> notFound(NoResourceFoundException e) {
        Map<String, Object> body = new LinkedHashMap<>();
        body.put("error", "not found");
        if (!props.secure()) {
            body.put("detail", e.getMessage());
        }
        return ResponseEntity.status(HttpStatus.NOT_FOUND).body(body);
    }

    @ExceptionHandler(Exception.class)
    public ResponseEntity<Map<String, Object>> any(Exception e) {
        Map<String, Object> body = new LinkedHashMap<>();
        if (props.secure()) {
            String id = UUID.randomUUID().toString();
            log.error("unhandled error {}", id, e);
            body.put("error", "internal error");
            body.put("reference", id);
        } else {
            StringWriter sw = new StringWriter();
            e.printStackTrace(new PrintWriter(sw));
            body.put("error", e.toString());
            body.put("trace", sw.toString());
        }
        return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body(body);
    }
}
