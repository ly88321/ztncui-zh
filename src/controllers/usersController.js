/*
  ztncui - ZeroTier network controller UI
  Copyright (C) 2017-2021  Key Networks (https://key-networks.com)
  Licensed under GPLv3 - see LICENSE for details.
*/

const fs = require('fs');
const argon2 = require('argon2');
const util = require('util');

const passwd_file = 'etc/passwd';
const min_pass_len = 10;

const readFile = util.promisify(fs.readFile);
const writeFile = util.promisify(fs.writeFile);
const chmod = util.promisify(fs.chmod);

let _users = null;

const get_users = async function() {
  if (_users) {
    return _users;
  } else {
    try {
      _users = JSON.parse(await readFile(passwd_file, 'utf8'));
      return _users;
    } catch(err) {
      throw(err);
    }
  }
}
exports.get_users = get_users;

const update_users = async function(users) {
  try {
    await writeFile(passwd_file, JSON.stringify(users), 'utf8');
    await chmod(passwd_file, 0600);

  } catch (err) {
    throw err;
  }
  _users = null;
  return await get_users();
}

exports.users_list = async function(req, res) {
  const navigate =
    {
      active: 'users',
    }

  try {
    const users = await get_users();
    res.render('users', { title: '管理用户', navigate: navigate, message: '列出具有管理员权限的用户列表', users: users });
  } catch (err) {
    res.render('users', { title: '管理用户', navigate: navigate, message: '错误', users: null, error: '返回用户列表时出错: ' + err });
  }
}

exports.password_get = async function(req, res) {
  const navigate =
    {
      active: 'users',
    }

  const user =
    {
      name: req.params.name,
      password1: null,
      password2: null
    };
  res.render('password', { title: '设置密码', navigate: navigate, user: user, readonly: true, message: '' });
}

exports.password_post = async function(req, res) {
  const navigate =
    {
      active: 'users',
    }

  req.checkBody('username', '需要用户名').notEmpty();
  req.sanitize('username').escape();
  req.sanitize('username').trim();

  req.checkBody('password1', '需要密码').notEmpty();
  req.checkBody('password1', '最小密码长度为 ' + min_pass_len + ' 字符').isLength({ min: min_pass_len, max: 160 });

  req.checkBody('password2', '请重新输入密码').notEmpty();
  req.checkBody('password2', '最小密码长度为 ' + min_pass_len + ' 字符').isLength({ min: min_pass_len, max: 160 });
  req.checkBody('password2', '两次输入密码不一样').equals(req.body.password1);

  const errors = req.validationErrors();

  if (errors) {
    const user =
      {
        name: req.body.username,
        password1: req.body.password1,
        password2: req.body.password2
      };
    const message = '请检查下面的错误';
    res.render('password', { title: '设置密码', navigate: navigate, user: user, readonly: true, message: message, errors: errors });
  } else {
    let pass_set = true;
    if (req.body.pass_set === 'check') pass_set = false;

    const hash = await argon2.hash(req.body.password1);

    const user =
      {
        name: req.body.username,
        pass_set: pass_set,
        hash: hash
      };

    const passwd_user =
      {
        [req.body.username]: user
      };

    let users = await get_users();
    users[req.body.username] = user;

    users = await update_users(users);

    const message = '已成功设置的密码为用户 ' + req.body.username;
    res.render('password', { title: '设置密码', navigate: navigate, user: user, readonly: true, message: message });
  }
}

exports.user_create_get = async function(req, res) {
  const navigate =
    {
      active: 'create_user',
    }

  const user =
    {
      name: null,
      password1: null,
      password2: null
    };

  res.render('password', { title: '创建新的管理员用户', navigate: navigate, user: user, readonly: false});
}

exports.user_create_post = async function(req, res) {
  const navigate =
    {
      active: 'create_user',
    }

  res.redirect(307, '/users/' + req.body.username + '/password');
}

exports.user_delete = async function(req, res) {
  const navigate =
    {
      active: 'users',
    }

  try {
    var users = await get_users();
  } catch (err) {
    throw err;
  }

  const user = users[req.params.name];

  if (user && (req.session.user.name === user.name)) {
    res.render('user_delete', { title: '删除用户', navigate: navigate, user: user, self_delete: true });
  }

  if (req.body.delete === 'delete') {
    if (user) {
      const deleted_user = { name: user.name };
      delete users[user.name];
      users = await update_users(users);
      res.render('user_delete', { title: '删除用户', navigate: navigate, user: deleted_user, deleted: true });
    } else {
      res.render('user_delete', { title: '删除用户', navigate: navigate, user: null });
    }
  } else {
    if (user) {
      res.render('user_delete', { title: '删除用户', navigate: navigate, user: user });
    } else {
      res.render('user_delete', { title: '删除用户', navigate: navigate, user: null });
    }
  }
}

