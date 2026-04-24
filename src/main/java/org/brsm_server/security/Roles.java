package org.brsm_server.security;

public final class Roles {

    private Roles() {}

    public static final String CHIEF = "hasAuthority('CHIEF_SECRETARY')";
    public static final String SECRETARIES = "hasAnyAuthority('SECRETARY','CHIEF_SECRETARY')";
    public static final String STUDENT = "hasAuthority('STUDENT')";
    public static final String ALL_AUTH = "hasAnyAuthority('STUDENT','SECRETARY','CHIEF_SECRETARY')";
}
