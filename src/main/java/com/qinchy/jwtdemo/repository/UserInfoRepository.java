package com.qinchy.jwtdemo.repository;

import com.qinchy.jwtdemo.model.UserInfo;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.CrudRepository;

import java.util.List;

/**
 * @author Administrator
 */
public interface UserInfoRepository extends CrudRepository<UserInfo, Integer> {
    /**
     * @param id
     * @return
     */
    UserInfo findUserInfoById(int id);

    /**
     * @param role
     * @return
     */
    List<UserInfo> findUserInfoByRole(String role);

    /**
     * @param count
     * @return
     */
    @Query(value = "select * from t_user limit ?1", nativeQuery = true)
    List<UserInfo> findAllUsersByCount(int count);

    /**
     * @param userName
     * @return
     */
    UserInfo findUserInfoByName(String userName);
}