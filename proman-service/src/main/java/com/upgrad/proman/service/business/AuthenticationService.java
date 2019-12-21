package com.upgrad.proman.service.business;

import com.upgrad.proman.service.dao.UserDao;
import com.upgrad.proman.service.entity.UserAuthTokenEntity;
import com.upgrad.proman.service.entity.UserEntity;
import com.upgrad.proman.service.exception.AuthenticationFailedException;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Propagation;
import org.springframework.transaction.annotation.Transactional;

import java.time.ZonedDateTime;

@Service
public class AuthenticationService {


    @Autowired
    private UserDao userDao;

    @Autowired
    private PasswordCryptographyProvider cryptographyProvider;

    @Transactional(propagation = Propagation.REQUIRED)
    public UserAuthTokenEntity authenticate(final String userName, final String password) throws AuthenticationFailedException {
        UserEntity userEntity = userDao.getUserByEmail( userName );
        if (userEntity == null) {
            throw new AuthenticationFailedException( "ATH-001", "User with email not found" );
        }

        String encryptedPassword = cryptographyProvider.encrypt( password, userEntity.getSalt() );

        if (encryptedPassword.equals( userEntity.getPassword() )) {
            JwtTokenProvider jwtTokenProvider = new JwtTokenProvider( encryptedPassword );
            UserAuthTokenEntity userAuthTokenEntity = new UserAuthTokenEntity();
            userAuthTokenEntity.setUser( userEntity );
            final ZonedDateTime now = ZonedDateTime.now();
            final ZonedDateTime expiresTime = now.plusHours( 8 );
            userAuthTokenEntity.setAccessToken( jwtTokenProvider.generateToken( userEntity.getUuid(), now, expiresTime ) );
            userAuthTokenEntity.setCreatedAt( now );
            userAuthTokenEntity.setExpiresAt( expiresTime );
            userAuthTokenEntity.setCreatedBy( "api-backend" );
            userAuthTokenEntity.setLoginAt( now );
            userDao.createAuthToken( userAuthTokenEntity );

            userEntity.setLastLoginAt( now );
            userDao.updateUser( userEntity );

            return userAuthTokenEntity;
        } else {
            throw new AuthenticationFailedException( "ATH-002", "Password failed" );
        }
    }
}
