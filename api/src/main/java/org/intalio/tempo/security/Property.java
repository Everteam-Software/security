/**
 * Copyright (C) 2003, Intalio Inc.
 *
 * The program(s) herein may be used and/or copied only with the
 * written permission of Intalio Inc. or in accordance with the terms
 * and conditions stipulated in the agreement/contract under which the
 * program(s) have been supplied.
 */

package org.intalio.tempo.security;

/**
 * Property consisting of a { name, value } pair.
 * <p>
 * @author <a href="http://www.intalio.com">&copy; Intalio Inc.</a>
 */
public final class Property
    implements java.io.Serializable
{
    private static final long serialVersionUID = -3413867511068365863L;

    /** Name */
    private String _name;
    
    /** Value */
    private Object _value;
    

	/**
	 * Default no-arg construct for use by serialization and unmarshalling.
	 */
	public Property()
	{
		// empty
	}

    /**
     * Construct a property with a given name and value.
     *
     * @param name Name of property
     * @param value Value of property
     */
    public Property( String name, Object value )
    {
        if ( name == null ) {
            throw new IllegalArgumentException( "Argument 'name' is null" );
        }
        _name = name;
        _value = value;
    }
    
    
    /**
     * Return the name of this property.
     */
    public String getName()
    {
        return _name;
    }

    
	/**
	 * Set the name of this property.
	 */
	public void setName( String name )
	{
		_name = name;
	}


    /**
     * Return the value of this property
     */
    public Object getValue()
    {
        return _value;
    }

    
	/**
	 * Set the value of this property.
	 */
	public void setValue( Object value )
	{
		_value = value;
	}


	/**
     * Return true if this object is equal to another.
     */
    @Override
    public boolean equals(Object obj) {
        if (this == obj)
            return true;
        if (obj == null)
            return false;
        if (getClass() != obj.getClass())
            return false;
        Property other = (Property) obj;
        if (_name == null) {
            if (other._name != null)
                return false;
        } else if (!_name.equals(other._name))
            return false;
        if (_value == null) {
            if (other._value != null)
                return false;
        } else if (!_value.equals(other._value))
            return false;
        return true;
    }


    /**
     * Obtain a String representation of this Property
     * 
     * @see java.lang.Object#toString()
     */
    public String toString() 
    {
        return "{"+_name+", "+_value+"}";
    }

    /**
     * Return a hash code for this object.
     */
    @Override
    public int hashCode() {
        final int prime = 31;
        int result = 1;
        result = prime * result + ((_name == null) ? 0 : _name.hashCode());
        result = prime * result + ((_value == null) ? 0 : _value.hashCode());
        return result;
    }
    
}