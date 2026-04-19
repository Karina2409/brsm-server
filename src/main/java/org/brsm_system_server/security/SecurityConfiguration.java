package org.brsm_system_server.security;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

@Configuration
@EnableWebSecurity
@RequiredArgsConstructor
@EnableGlobalMethodSecurity(prePostEnabled = true)
@Slf4j
public class SecurityConfiguration {

    private final JwtAuthenticationFilter jwtAuthFilter;

    @Autowired
    private AuthenticationProvider authenticationProvider;

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        http
                .cors(Customizer.withDefaults())
                .csrf(csrf -> csrf.disable())
                .authorizeHttpRequests(authorize -> authorize
                        .requestMatchers("/brsm/auth/authenticate",
                                "/brsm/auth/signUp",
                                "/students/{studentId}/events",
                                "/students/{studentId}",
                                "/events/{eventId}")
                        .permitAll()
                        .requestMatchers(HttpMethod.GET, "/students/get-all").hasAnyAuthority("SECRETARY", "CHIEF_SECRETARY")
                        .requestMatchers(HttpMethod.GET, "/users").hasAuthority("CHIEF_SECRETARY")
                        .requestMatchers(HttpMethod.PATCH, "/users/{userId}/role").hasAuthority("CHIEF_SECRETARY")
                        .requestMatchers(HttpMethod.GET, "/events/get-all").hasAnyAuthority("SECRETARY", "CHIEF_SECRETARY")
                        .requestMatchers(HttpMethod.PUT, "/events/event/update/{eventId}").hasAnyAuthority("SECRETARY", "CHIEF_SECRETARY")
                        .requestMatchers(HttpMethod.GET, "/events/past").hasAnyAuthority("SECRETARY", "CHIEF_SECRETARY", "STUDENT")
                        .requestMatchers(HttpMethod.GET, "/events/eventStatistics").hasAnyAuthority("SECRETARY", "CHIEF_SECRETARY")
                        .requestMatchers(HttpMethod.DELETE, "/events/delete/{eventId}").hasAnyAuthority("SECRETARY", "CHIEF_SECRETARY")
                        .requestMatchers(HttpMethod.POST, "/events/post").hasAnyAuthority("SECRETARY", "CHIEF_SECRETARY")
                        .requestMatchers(HttpMethod.GET, "/exemptions/get-all").hasAnyAuthority("SECRETARY", "CHIEF_SECRETARY")
                        .requestMatchers(HttpMethod.DELETE, "/exemptions/delete/{exemptionId}").hasAnyAuthority("SECRETARY", "CHIEF_SECRETARY")
                        .requestMatchers(HttpMethod.POST, "/exemptions/download/{exemptionId}").hasAnyAuthority("SECRETARY", "CHIEF_SECRETARY")
                        .requestMatchers(HttpMethod.POST, "/exemptions/post/{eventId}").hasAnyAuthority("SECRETARY", "CHIEF_SECRETARY")
                        .requestMatchers(HttpMethod.GET, "/reports/get-all").hasAnyAuthority("SECRETARY", "CHIEF_SECRETARY")
                        .requestMatchers(HttpMethod.DELETE, "/reports/delete/{reportId}").hasAnyAuthority("SECRETARY", "CHIEF_SECRETARY")
                        .requestMatchers(HttpMethod.POST, "/reports/post/month").hasAnyAuthority("SECRETARY", "CHIEF_SECRETARY")
                        .requestMatchers(HttpMethod.POST, "/reports/download/{reportId}").hasAnyAuthority("SECRETARY", "CHIEF_SECRETARY")
                        .requestMatchers(HttpMethod.GET, "/petitions/get-all").hasAnyAuthority("SECRETARY", "CHIEF_SECRETARY")
                        .requestMatchers(HttpMethod.POST, "/petitions/download/{petitionId}").hasAnyAuthority("SECRETARY", "CHIEF_SECRETARY")
                        .requestMatchers(HttpMethod.DELETE, "/petitions/delete/{petitionId}").hasAnyAuthority("SECRETARY", "CHIEF_SECRETARY")
                        .requestMatchers(HttpMethod.GET, "/petitions/eligible").hasAnyAuthority("SECRETARY", "CHIEF_SECRETARY")
                        .requestMatchers(HttpMethod.POST, "/petitions/post/{studentId}").hasAnyAuthority("SECRETARY", "CHIEF_SECRETARY")
                        .requestMatchers(HttpMethod.POST, "/students/import").hasAnyAuthority("SECRETARY", "CHIEF_SECRETARY")

                        .requestMatchers(HttpMethod.GET, "/events/upcoming").hasAuthority("STUDENT")
                        .requestMatchers(HttpMethod.GET, "/secretaries/get-all").hasAuthority("STUDENT")
                        .requestMatchers(HttpMethod.GET, "/users/student/{userId}").hasAuthority("STUDENT")
                        .requestMatchers(HttpMethod.POST, "/se/{studentId}/events/{eventId}").hasAuthority("STUDENT")
                        .requestMatchers(HttpMethod.DELETE, "/se/remove/student/{studentId}/event/{eventId}").hasAuthority("STUDENT")
                        .requestMatchers(HttpMethod.PUT, "/students/student/{studentId}").hasAuthority("STUDENT")
//                        .requestMatchers(HttpMethod.GET, "/students/**").hasAuthority("SECRETARY")
//
                        .anyRequest().authenticated())
                .sessionManagement(session -> session.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
                .authenticationProvider(authenticationProvider)
                .addFilterBefore(jwtAuthFilter, UsernamePasswordAuthenticationFilter.class);

        return http.build();
    }

}
