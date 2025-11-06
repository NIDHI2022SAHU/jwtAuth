package com.example.day2jwt.advice;

import com.example.day2jwt.dto.ApiResponse;
import com.example.day2jwt.exception.ApiException;
import jakarta.validation.ConstraintViolationException;
import lombok.extern.slf4j.Slf4j;
import org.springframework.core.Ordered;
import org.springframework.core.annotation.Order;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.HttpStatusCode;
import org.springframework.http.ResponseEntity;
import org.springframework.http.converter.HttpMessageNotReadableException;
import org.springframework.web.bind.MethodArgumentNotValidException;
import org.springframework.web.bind.annotation.ControllerAdvice;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.ResponseStatus;
import org.springframework.web.context.request.WebRequest;
import org.springframework.web.servlet.NoHandlerFoundException;
import org.springframework.web.servlet.mvc.method.annotation.ResponseEntityExceptionHandler;
import java.util.stream.Collectors;

@Slf4j
@Order(Ordered.HIGHEST_PRECEDENCE)
@ControllerAdvice
public class GlobalExceptionHandler extends ResponseEntityExceptionHandler {

    // Handle route not found
    @Override
    protected ResponseEntity<Object> handleNoHandlerFoundException(
            NoHandlerFoundException ex, HttpHeaders headers, HttpStatusCode status, WebRequest request) {

        ApiResponse<Object> response = new ApiResponse<>(
                HttpStatus.NOT_FOUND.value(),
                "Route not found",
                null,
                "Check the URL");
        return ResponseEntity.status(HttpStatus.NOT_FOUND).body(response);
    }

    // Handle custom ApiException
    @ExceptionHandler(ApiException.class)
    protected ResponseEntity<ApiResponse<Object>> handleApiException(ApiException ex) {
        HttpStatus status = deduceStatusFromAnnotation(ex);
        ApiResponse<Object> response = new ApiResponse<>(
                status.value(),
                ex.getMessage(),
                null,
                "Please check your request and try again");
        log.warn("API Exception: {}", ex.getMessage());
        return ResponseEntity.status(status).body(response);
    }

    // Handle @Valid validation errors
    @Override
    protected ResponseEntity<Object> handleMethodArgumentNotValid(
            MethodArgumentNotValidException ex, HttpHeaders headers, HttpStatusCode status, WebRequest request) {

        String details = ex.getBindingResult()
                .getFieldErrors()
                .stream()
                .map(e -> e.getField() + ": " + e.getDefaultMessage())
                .collect(Collectors.joining(", "));

        ApiResponse<Object> response = new ApiResponse<>(
                HttpStatus.BAD_REQUEST.value(),
                "Validation failed: " + details,
                null,
                "Correct the input fields");
        log.info("Validation failed: {}", details);
        return ResponseEntity.badRequest().body(response);
    }

    // Handle malformed JSON
    @Override
    protected ResponseEntity<Object> handleHttpMessageNotReadable(
            HttpMessageNotReadableException ex, HttpHeaders headers, HttpStatusCode status, WebRequest request) {

        ApiResponse<Object> response = new ApiResponse<>(
                HttpStatus.BAD_REQUEST.value(),
                "Malformed JSON request",
                null,
                "Check the request body");
        log.warn("Malformed JSON: {}", ex.getMessage());
        return ResponseEntity.badRequest().body(response);
    }

    // Handle constraint violations
    @ExceptionHandler(ConstraintViolationException.class)
    public ResponseEntity<ApiResponse<Object>> handleConstraintViolation(ConstraintViolationException ex) {

        String details = ex.getConstraintViolations()
                .stream()
                .map(cv -> cv.getPropertyPath() + ": " + cv.getMessage())
                .collect(Collectors.joining(", "));

        ApiResponse<Object> response = new ApiResponse<>(
                HttpStatus.BAD_REQUEST.value(),
                "Validation error: " + details,
                null,
                "Correct the request parameters");
        return ResponseEntity.badRequest().body(response);
    }

    // Handle generic/unexpected errors
    @ExceptionHandler(Exception.class)
    public ResponseEntity<ApiResponse<Object>> handleGenericException(Exception ex) {
        log.error("Unexpected error", ex);
        ApiResponse<Object> response = new ApiResponse<>(
                HttpStatus.INTERNAL_SERVER_ERROR.value(),
                ex.getMessage(),
                null,
                "Contact support");
        return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body(response);
    }

    private HttpStatus deduceStatusFromAnnotation(Throwable ex) {
        ResponseStatus rs = ex.getClass().getAnnotation(ResponseStatus.class);
        return (rs != null) ? rs.code() : HttpStatus.BAD_REQUEST;
    }

    // Handle wrong HTTP method (e.g., GET on POST endpoint)
    @Override
    protected ResponseEntity<Object> handleHttpRequestMethodNotSupported(
            org.springframework.web.HttpRequestMethodNotSupportedException ex,
            HttpHeaders headers,
            HttpStatusCode status,
            WebRequest request) {

        String message = String.format("HTTP method '%s' not supported for this endpoint. Supported methods: %s",
                ex.getMethod(), ex.getSupportedHttpMethods());

        ApiResponse<Object> response = new ApiResponse<>(
                HttpStatus.METHOD_NOT_ALLOWED.value(),
                message,
                null,
                "Use the correct HTTP method as per API documentation");

        log.warn("Method not allowed: {}", message);
        return ResponseEntity.status(HttpStatus.METHOD_NOT_ALLOWED).body(response);
    }

}
