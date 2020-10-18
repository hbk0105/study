package com.boot.study.filter;

import com.boot.study.HomeController;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.authentication.logout.LogoutSuccessHandler;
import org.springframework.security.web.authentication.logout.SecurityContextLogoutHandler;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

public class CustomLogoutSuccessHandler implements LogoutSuccessHandler{


    private Logger logger = LoggerFactory.getLogger(CustomLogoutSuccessHandler.class);

    @Override
    public void onLogoutSuccess(HttpServletRequest request, HttpServletResponse response,
                                Authentication authentication) throws IOException, ServletException {

        logger.info("@@@ onLogoutSuccess !! ");

        try {
            logger.info("@@@ onLogoutSuccess 2222222222 ");

            request.getSession().invalidate();
            //SecurityContextHolder.getContext().setAuthentication(null);
            new SecurityContextLogoutHandler().logout(request, null, null);

        } catch (Exception e) {
            e.printStackTrace();
        }

        response.setStatus(HttpServletResponse.SC_OK);
        response.sendRedirect("/");
    }
}