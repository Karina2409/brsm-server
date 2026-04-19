package org.brsm_system_server.help;

public class InputCheck {
    public boolean isNumeric(String inputString) {
        try {
            int number = Integer.parseInt(inputString);
            return true;
        } catch (NumberFormatException e) {
            return false;
        }
    }
}