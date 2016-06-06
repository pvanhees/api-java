package com.nauth.api;

import java.util.Date;

/**
 * Created by pieter on 4/25/16.
 */
public class NAuthAccount {

    private Long id;
    private boolean publicKeyAuthRevoked;
    private boolean publicKeyTransRevoked;
    private String description;
    private Date lastLogin;
    private Date creationDate;
    private boolean blocked;

    public NAuthAccount(Long id, boolean publicKeyAuthRevoked, boolean publicKeyTransRevoked, String description, Date lastLogin, Date creationDate, boolean blocked) {
        this.id = id;
        this.publicKeyAuthRevoked = publicKeyAuthRevoked;
        this.publicKeyTransRevoked = publicKeyTransRevoked;
        this.description = description;
        this.lastLogin = lastLogin;
        this.creationDate = creationDate;
        this.blocked = blocked;
    }

    public Long getId() {
        return id;
    }

    public boolean isPublicKeyAuthRevoked() {
        return publicKeyAuthRevoked;
    }

    public boolean isPublicKeyTransRevoked() {
        return publicKeyTransRevoked;
    }

    public String getDescription() {
        return description;
    }

    public Date getLastLogin() {
        return lastLogin;
    }

    public Date getCreationDate() {
        return creationDate;
    }

    public boolean isBlocked() {
        return blocked;
    }

    @Override
    public boolean equals(final Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;

        final NAuthAccount that = (NAuthAccount) o;

        if (!id.equals(that.id)) return false;
        if (!description.equals(that.description)) return false;
        return creationDate.equals(that.creationDate);

    }

    @Override
    public int hashCode() {
        int result = id.hashCode();
        result = 31 * result + description.hashCode();
        result = 31 * result + creationDate.hashCode();
        return result;
    }
}
