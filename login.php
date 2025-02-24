<?php
session_start();
include("./settings/connect_datebase.php");

if (isset($_SESSION['user']) && $_SESSION['user'] != -1) {
    $stmt = $mysqli->prepare("SELECT role FROM users WHERE id = ?");
    $stmt->bind_param("i", $_SESSION['user']);
    $stmt->execute();
    $stmt->bind_result($role);
    $stmt->fetch();
    $stmt->close();

    if ($role == 0) {
        header("Location: user.php");
        exit();
    } elseif ($role == 1) {
        header("Location: admin.php");
        exit();
    }
}
?>
<!DOCTYPE html>
<html lang="ru">
<head>
    <meta charset="utf-8">
    <title>Авторизация</title>
    <script src="https://code.jquery.com/jquery-3.6.0.min.js"></script>
    <script src="https://www.google.com/recaptcha/api.js" async defer></script>
    <link rel="stylesheet" href="style.css">
</head>
<body>
    <div class="top-menu">
        <a href="#"><img src="img/logo1.png"/></a>
        <div class="name">
            <a href="index.php">
                <div class="subname">БЕЗОПАСНОСТЬ ВЕБ-ПРИЛОЖЕНИЙ</div>
                Пермский авиационный техникум им. А. Д. Швецова
            </a>
        </div>
    </div>

    <div class="main">
        <div class="content">
            <div class="login">
                <div class="name">Авторизация</div>
                <form id="loginForm">
                    <div class="sub-name">Логин:</div>
                    <input name="login" type="text" placeholder="Введите логин" required>
                    <div class="sub-name">Пароль:</div>
                    <input name="password" type="password" placeholder="Введите пароль" required>
                    <center>
                        <div class="g-recaptcha" data-sitekey="6LcDReAqAAAAAEDozYn2nNvaBLbhokyfHaqQqcIK"></div>
                    </center>
                    <a href="regin.php">Регистрация</a>
                    <br>
                    <a href="recovery.php">Забыли пароль?</a>
                    <input type="submit" class="button" value="Войти">
                    <img src="img/loading.gif" class="loading" style="display: none;">
                </form>
            </div>
        </div>
    </div>

    <script>
        $("#loginForm").submit(function (e) {
            e.preventDefault();
            let loading = $(".loading");
            let button = $(".button");
            let captcha = grecaptcha.getResponse();
            let login = $("input[name='login']").val().trim();
            let password = $("input[name='password']").val().trim();

            if (!login || !password) {
                alert("Ошибка: Заполните все поля!");
                return;
            }

            if (!captcha.length) {
                alert("Ошибка: reCAPTCHA не пройдена!");
                return;
            }

            loading.show();
            button.prop("disabled", true);

            $.ajax({
                url: "ajax/login_user.php",
                type: "POST",
                data: {
                    "g-recaptcha-response": captcha,
                    "login": login,
                    "password": password
                },
                dataType: "json",
                success: function (response) {
                    if (response.status === "success") {
                        window.location.href = response.redirect;
                    } else {
                        alert(response.message || "Ошибка авторизации!");
                        grecaptcha.reset();
                    }
                    loading.hide();
                    button.prop("disabled", false);
                },
                error: function (xhr) {
                    alert("Ошибка сервера: " + xhr.responseText);
                    loading.hide();
                    button.prop("disabled", false);
                }
            });
        });
    </script>
</body>
</html>
