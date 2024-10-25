package dev.roshin.saml.services.config;

import com.google.gson.Gson;
import com.google.gson.reflect.TypeToken;

import java.util.Collections;
import java.util.Map;

public class JsonUtils {
    private static final Gson gson = new Gson();

    public static Map<String, String> parseJson(String jsonString) {
        if (jsonString == null || jsonString.trim().isEmpty()) {
            return Collections.emptyMap();
        }

        try {
            TypeToken<Map<String, String>> typeToken = new TypeToken<>() {
            };
            return gson.fromJson(jsonString, typeToken.getType());
        } catch (Exception e) {
            throw new RuntimeException("Failed to parse JSON string: " + e.getMessage(), e);
        }
    }

    // Optional: Add method to convert Map to JSON string
    public static String toJson(Map<String, String> map) {
        if (map == null) {
            return "{}";
        }
        return gson.toJson(map);
    }
}
