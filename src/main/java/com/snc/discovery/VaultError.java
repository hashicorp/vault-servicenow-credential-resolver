/*
 * Copyright IBM Corp. 2021, 2026
 * SPDX-License-Identifier: MPL-2.0
 */

package com.snc.discovery;

public class VaultError {
    private String[] warnings;
    private String[] errors;

    public String[] getWarnings() {
        return warnings;
    }

    public String[] getErrors() {
        return errors;
    }
}
