package org.intalio.tempo.security.rbac;

public class RoleExistsException extends RBACException {
    private static final long serialVersionUID = -5673950029436827800L;

    /**
     * Construct a new RoleExistsException exception wrapping an underlying exception
     * and providing a message.
     *
     * @param message The exception message
     * @param except The underlying exception
     */
    public RoleExistsException(String message, Exception except) {
        super(message, except);
    }

    /**
     * Construct a new RoleExistsException exception with a message.
     *
     * @param message The exception message
     */
    public RoleExistsException(String message) {
        super(message);
    }

    /**
     * Construct a new RoleExistsException exception wrapping an underlying exception.
     *
     * @param except The underlying exception
     */
    public RoleExistsException(Exception except) {
        super(except);
    }

}
