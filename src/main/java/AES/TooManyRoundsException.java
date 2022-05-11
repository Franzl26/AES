package AES;

public class TooManyRoundsException extends RuntimeException{
    public TooManyRoundsException() {
    }

    public TooManyRoundsException(String message) {
        super(message);
    }

    public TooManyRoundsException(String message, Throwable cause) {
        super(message, cause);
    }

    public TooManyRoundsException(Throwable cause) {
        super(cause);
    }
}
