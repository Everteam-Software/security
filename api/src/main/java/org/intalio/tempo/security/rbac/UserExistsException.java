package org.intalio.tempo.security.rbac;

public class UserExistsException extends RBACException {
    private static final long serialVersionUID = -5673950029436827800L;

    /**
     * Construct a new UserExistsException exception wrapping an underlying exception
     * and providing a message.
     *
     * @param message The exception message
     * @param except The underlying exception
     */
    public UserExistsException(String message, Exception except) {
        super(message, except);
    }

    /**
     * Construct a new UserExistsException exception with a message.
     *
     * @param message The exception message
     */
    public UserExistsException(String message) {
        super(message);
    }

    /**
     * Construct a new UserExistsException exception wrapping an underlying exception.
     *
     * @param except The underlying exception
     */
    public UserExistsException(Exception except) {
        super(except);
    }

}