package com.ding.service;

import com.ding.dao.UserDao;
import com.ding.entities.User;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Component;
import org.springframework.util.ObjectUtils;

@Component
public class MyUserDetailService implements UserDetailsService {

    private final UserDao userDao;

    @Autowired
    public MyUserDetailService(UserDao userDao) {
        this.userDao = userDao;
    }

    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        System.out.println(username);
        User user = userDao.loadUserByUsername(username);
        System.out.println(user.toString());
        if (ObjectUtils.isEmpty(user)) throw new RuntimeException("用户不存在");
        user.setRoles(userDao.getRolesByUid(user.getId()));
        return user;
    }
}