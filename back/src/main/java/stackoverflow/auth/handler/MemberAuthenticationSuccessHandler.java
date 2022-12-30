package stackoverflow.auth.handler;

import com.google.gson.Gson;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.MediaType;
import org.springframework.security.core.Authentication;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import stackoverflow.auth.dto.LoginResponseDto;
import stackoverflow.member.entity.Member;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

@Slf4j
public class MemberAuthenticationSuccessHandler implements AuthenticationSuccessHandler {
    @Override
    public void onAuthenticationSuccess(HttpServletRequest request,
                                        HttpServletResponse response,
                                        Authentication authentication) throws IOException {

        log.info("# Authenticated successfully!");
    }
    private void sendSuccessResponse(HttpServletResponse response,
                                     Authentication authentication) throws IOException {
        Gson gson = new Gson();
        Member member = (Member) authentication.getPrincipal();
        LoginResponseDto dto = new LoginResponseDto();
        dto.setMemberId(member.getMemberId());
        dto.setPassword(member.getPassword());
        dto.setEmail(member.getEmail());
        response.setContentType(MediaType.APPLICATION_JSON_VALUE);
        response.getWriter().write(gson.toJson(dto, LoginResponseDto.class));
    }
}
