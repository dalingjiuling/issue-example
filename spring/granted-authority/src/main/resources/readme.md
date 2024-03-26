问题： GrantedAuthority 如何对应到用户的角色
相关知识：
Hierarchical Roles 用来对GrantedAuthority分层级

表：sys_role 用户角色
GrantedAuthority 和 role_key对应，
用户包含多个角色，它获取的菜单是两个角色的合并

客户端scope 作用域，不能和这里的GrantedAuthority要区分