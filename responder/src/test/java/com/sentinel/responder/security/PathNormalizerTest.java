package com.sentinel.responder.security;

import static org.assertj.core.api.Assertions.assertThat;

import java.util.List;
import java.util.Optional;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;
import org.junit.jupiter.params.provider.ValueSource;

class PathNormalizerTest {

    @ParameterizedTest
    @CsvSource(delimiter = '|', value = {
        "/|/",
        "/admin/users|/admin/users",
        "//admin//users|/admin/users",
        "/admin/./users|/admin/users",
        "/x/../admin/users|/admin/users",
        "/a/b/../../admin|/admin",
        "/../../admin|/admin",
        "/%61dmin/users|/admin/users",
        "/%2561dmin/users|/admin/users",
        "/admin;jsessionid=1/users|/admin/users",
        "/admin/users;x=y|/admin/users",
        "/admin%5Cusers|/admin/users",
        "/ADMIN/Users|/ADMIN/Users",
        "/%2e%2e/admin|/admin",
        "/%252e%252e/admin|/admin",
        "/products/1/|/products/1",
    })
    void canonicalisesEveryBypassForm(String raw, String expected) {
        assertThat(PathNormalizer.normalize(raw)).contains(expected);
    }

    @ParameterizedTest
    @ValueSource(strings = {"", "admin", "/admin%", "/admin%2", "/admin%zz", "/admin%00", "/admin%0d%0aX: y", "/a%0ab",
        "/%ff%fe", "/\u0000", "/admin\u007f"})
    void rejectsMalformedOrSuspiciousPaths(String raw) {
        assertThat(PathNormalizer.normalize(raw)).isEmpty();
    }

    @Test
    void rejectsNullAndOversizedPaths() {
        assertThat(PathNormalizer.normalize(null)).isEmpty();
        assertThat(PathNormalizer.normalize("/" + "a".repeat(3000))).isEmpty();
    }

    @ParameterizedTest
    @CsvSource({"/admin,true", "/admin/users,true", "/Admin/x,true", "/ADMIN,true", "/administrator,false", "/adm,false", "/x/admin,false", "/,false"})
    void prefixMatchIsCaseInsensitiveAndSegmentAware(String path, boolean expected) {
        assertThat(PathNormalizer.under(path, "/admin")).isEqualTo(expected);
    }

    @Test
    void underAnyChecksAllPrefixes() {
        assertThat(PathNormalizer.underAny("/internal/x", List.of("/admin", "/internal"))).isTrue();
        assertThat(PathNormalizer.underAny("/public", List.of("/admin", "/internal"))).isFalse();
    }

    @Test
    void encodeKeepsOnlySafeCharactersLiteral() {
        assertThat(PathNormalizer.encode("/a b/ü?#%")).isEqualTo("/a%20b/%C3%BC%3F%23%25");
        assertThat(PathNormalizer.encode("/admin/users-1_2.3~")).isEqualTo("/admin/users-1_2.3~");
    }

    @Test
    void normalisedPathIsStableWhenNormalisedAgain() {
        Optional<String> once = PathNormalizer.normalize("/x/../%61dmin;p=1//users");
        assertThat(once).contains("/admin/users");
        assertThat(PathNormalizer.normalize(once.get())).isEqualTo(once);
    }
}
