package com.upgrad.proman.service.exception;

import java.io.PrintStream;
import java.io.PrintWriter;

public class UnauthorizedException extends Exception {

    private final String code;
    private final String errorMessage;

    public UnauthorizedException(final String code, final String errorMessage){
        this.code = code;
        this.errorMessage = errorMessage;
    }

    public String getCode(){
        return this.code;
    }

    public String getErrorMessage(){
        return this.errorMessage;
    }

    @Override
    public void printStackTrace() {
        super.printStackTrace();
    }

    @Override
    public void printStackTrace(PrintStream s) {
        super.printStackTrace( s );
    }

    @Override
    public void printStackTrace(PrintWriter s) {
        super.printStackTrace( s );
    }
}
