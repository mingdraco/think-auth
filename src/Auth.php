<?php

// +------------------------------------------------------------------------
// | CuiCMS
// +------------------------------------------------------------------------
// | Copyright (c) 2014-2017 http://www.cuiyuanxin.com, All rights reserved.
// +------------------------------------------------------------------------
// | Author: cuiyuanxin <15811506097@163.com>
// +------------------------------------------------------------------------

/**
 * 权限认证类
 * 功能特性：
 * 1，是对规则进行认证，不是对节点进行认证。用户可以把节点当作规则名称实现对节点进行认证。
 *      $auth=new Auth();  $auth->check('规则名称','用户id')
 * 2，可以同时对多条规则进行认证，并设置多条规则的关系（or或者and）
 *      $auth=new Auth();  $auth->check('规则1,规则2','用户id','and')
 *      第三个参数为and时表示，用户需要同时具有规则1和规则2的权限。 当第三个参数为or时，表示用户值需要具备其中一个条件即可。默认为or
 * 3，一个用户可以属于多个用户组(think_auth_group_access表 定义了用户所属用户组)。我们需要设置每个用户组拥有哪些规则(think_auth_group 定义了用户组权限)
 *
 * 4，支持规则表达式。
 *      在think_auth_rule 表中定义一条规则时，如果type为1， condition字段就可以定义规则表达式。 如定义{score}>5  and {score}<100  表示用户的分数在5-100之间时这条规则才会通过。
 */

namespace think\auth;

use think\Db;
use think\Config;
use think\Session;
use think\Cookie;
use think\Request;

class Auth {

    /**
     * 用户session变量空间
     */
    protected static $prefix = 'auth';

    /**
     * 当前请求实例
     * @var Request
     */
    protected $request;
    //默认配置
    protected $config = [
        'auth_on' => true, // 认证开关
        'auth_type' => 1, // 认证方式，1为实时认证；2为登录认证。
        'auth_group' => 'auth_group', // 用户组数据表名
        'auth_group_access' => 'auth_group_access', // 用户-用户组关系表
        'auth_rule' => 'auth_rule', // 权限规则表
        'auth_user' => 'member'             // 用户信息表
    ];

    public function __construct() {
        //可设置配置项 auth, 此配置项为数组。
        if ($auth = Config::get('auth')) {
            $this->config = array_merge($this->config, $auth);
        }
        // 初始化request
        $this->request = Request::instance();
    }

    /**
     * 检查权限
     * @param string|array $name   需要验证的规则列表,支持逗号分隔的权限规则或索引数组
     * @param   int  $uid         认证用户的id
     * @param int $type        执行check的模式
     * @param string $mode        执行check的模式
     * @param string $relation    如果为 'or' 表示满足任一条规则即通过验证;如果为 'and'则表示需满足所有规则才能通过验证
     * @return boolean           通过验证返回true;失败返回false
     */
    public function check($name, $uid, $type = 1, $mode = 'url', $relation = 'or') {
        if (!$this->config['auth_on']) {
            return true;
        }
        $authList = $this->getAuthList($uid, $type); //获取用户需要验证的所有有效规则列表
        if (is_string($name)) {
            $name = strtolower($name);
            if (strpos($name, ',') !== false) {
                $name = explode(',', $name);
            } else {
                $name = [$name];
            }
        }
        $list = []; //保存验证通过的规则名
        if ($mode == 'url') {
            $REQUEST = unserialize(strtolower(serialize($this->request->param())));
        }
        foreach ($authList as $auth) {
            $query = preg_replace('/^.+\?/U', '', $auth);
            if ($mode == 'url' && $query != $auth) {
                parse_str($query, $param); //解析规则中的param
                $intersect = array_intersect_assoc($REQUEST, $param);
                $auth = preg_replace('/\?.*$/U', '', $auth);
                if (in_array($auth, $name) && $intersect == $param) {
                    //如果节点相符且url参数满足
                    $list[] = $auth;
                }
            } else {
                if (in_array($auth, $name)) {
                    $list[] = $auth;
                }
            }
        }
        if ($relation == 'or' && !empty($list)) {
            return true;
        }
        $diff = array_diff($name, $list);
        if ($relation == 'and' && empty($diff)) {
            return true;
        }
        return false;
    }

    /**
     * 根据用户id获取用户组,返回值为数组
     * @param  int  $uid    用户id
     * @return array       用户所属的用户组 array(
     *     array('uid'=>'用户id','group_id'=>'用户组id','title'=>'用户组名称','rules'=>'用户组拥有的规则id,多个,号隔开'),
     *     ...)
     */
    public function getGroups($uid) {
        static $groups = [];
        if (isset($groups[$uid])) {
            return $groups[$uid];
        }
        $user_groups = db()->name($this->config['auth_group_access'] . ' a')
                        ->where("a.uid='$uid' and g.status='1'")
                        ->join(config('database.prefix') . "{$this->config['auth_group']} g", " a.group_id = g.id")
                        ->field('uid,group_id,title,rules')->select();
        $groups[$uid] = $user_groups ? : array();
        return $groups[$uid];
    }

    /**
     * 获得权限列表
     * @param integer $uid  用户id
     * @param integer $type
     */
    protected function getAuthList($uid, $type) {
        static $_authList = []; //保存用户验证通过的权限列表
        $t = implode(',', (array) $type);
        if (isset($_authList[$uid . $t])) {
            return $_authList[$uid . $t];
        }
        if ($this->config['auth_type'] == 2 && Session::has('_auth_list_' . $uid . $t)) {
            return Session::get('_auth_list_' . $uid . $t);
        }
        //读取用户所属用户组
        $groups = $this->getGroups($uid);
        $ids = []; //保存用户所属用户组设置的所有权限规则id
        foreach ($groups as $g) {
            $ids = array_merge($ids, explode(',', trim($g['rules'], ',')));
        }
        $ids = array_unique($ids);
        if (empty($ids)) {
            $_authList[$uid . $t] = [];
            return [];
        }
        $map = array(
            'id' => ['in', $ids],
            'type' => $type,
            'status' => 1,
        );
        //读取用户组所有权限规则
        $rules = db()->name($this->config['auth_rule'])->where($map)->field('condition,name')->select();
        //循环规则，判断结果。
        $authList = [];
        foreach ($rules as $rule) {
            if (!empty($rule['condition'])) { //根据condition进行验证
                $user = $this->getUserInfo($uid); //获取用户信息,一维数组
                $command = preg_replace('/\{(\w*?)\}/', '$user[\'\\1\']', $rule['condition']);
                //dump($command);//debug
                @(eval('$condition=(' . $command . ');'));
                if (isset($condition)) {
                    $authList[] = strtolower($rule['name']);
                }
            } else {
                //只要存在就记录
                $authList[] = strtolower($rule['name']);
            }
        }
        $_authList[$uid . $t] = $authList;
        if ($this->config['auth_type'] == 2) {
            //规则列表结果保存到session
            Session::set('_auth_list_' . $uid . $t, $authList);
        }
        return array_unique($authList);
    }

    /**
     * 获得用户资料,根据自己的情况读取数据库
     */
    protected function getUserInfo($uid) {
        static $userinfo = [];
        $user = Db::name($this->config['auth_user']);
        // 获取用户表主键
        $_pk = is_string($user->getPk()) ? $user->getPk() : 'uid';
        if (!isset($userinfo[$uid])) {
            $userinfo[$uid] = $user->where($_pk, $uid)->find();
        }
        return $userinfo[$uid];
    }

    /**
     * 注册用户信息
     * @参数1 $name
     *   1. 数组：覆盖用户信息
     *   2. 为空：返回用户信息
     *   3. 字符串
     *     3.1 未传入参数2：返回user[$name]
     *     3.2 传入参数2：   设置user[$name] = $value
     * @参数2 $value 当传入该参数时，为赋值操作
     * @参数2 $type 返回是session还是cookie/或者是否设置cookie
     */
    public static function user($name = null, $value = null, $type = false) {
        if (is_array($name)) {
            if ($type) {
                Cookie::set('user', $name, self::$prefix);
            } else {
                Session::set('user', $name, self::$prefix);
            }
        } elseif (empty($name)) {
            if ($type) {
                return Cookie::get('user', self::$prefix);
            } else {
                return Session::get('user', self::$prefix);
            }
        } elseif (is_string($name) && null === $value) {
            if ($type) {
                return Cookie::get('user.' . $name, self::$prefix);
            } else {
                return Session::get('user.' . $name, self::$prefix);
            }
        } elseif (is_string($name)) {
            if ($type) {
                Cookie::set('user.' . $name, $value, self::$prefix);
            } else {
                Session::set('user.' . $name, $value, self::$prefix);
            }
        } else {
            return null;
        }
    }

    /**
     * 注销用户信息
     */
    public static function clear() {
        Session::delete('user', self::$prefix);
        Cookie::delete('user', self::$prefix);
    }

}
