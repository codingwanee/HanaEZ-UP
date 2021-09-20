<%@ page language="java" contentType="text/html; charset=UTF-8"
    pageEncoding="UTF-8"%>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>Title</title>
    <link rel="stylesheet" href="${ pageContext.request.contextPath }/resources/css/style.css"/>
    <link rel="stylesheet" href="${ pageContext.request.contextPath }/resources/css/hana-ez-up.css"/>
    <script>
    
    new Notification("타이틀", {body:'메세지내용'});

    
 // 알림 띄우기
    function notify(msg) {
        var options = {
            body: msg
        }
        
        // 데스크탑 알림 요청
        var notification = new Notification("DororongJu", options);
        
        // 3초뒤 알람 닫기
        setTimeout(function(){
            notification.close();
        }, 3000);
    }

    </script>
</head>
<body>
<div id="HANA_CONTENTS_DIV">


    <!-- /////////////// 언어선택 //////////////////// -->

    <div id="language">
        <div id="lang-select" class="lang-select">
            <h3>Languages</h3>
            <div class="lang-sw lang-kor" data-lang="lang_kor">
                <a href="/kor/">
                <span class="lang-title">
                    한국어<br>(Korean)
                </span>
                </a>
            </div>

        </div>
    </div>

    <div>

        <button class="btn secondary">aa</button>
    </div>

    <!-- /////////////// 환율검색 //////////////////// -->

    <section class="exchange-rate">
        <div class="container-fluid" id="exchange-rate">

            <h3> Preview Transfer </h3>
            <div class="row">
                <div class="col-sm-4 off-2">
                    <div class="exchange-before">
                        <input type="text" name="before" class="before" title="Deposit amount">
                        <span class="krw">krw<span class="flag-kor">flag</span>KRW</span>
                    </div>
                </div>
                <div class="col-sm-4">
                    <div class="exchange-after">
                        <input type="tel" class="after" tabindex="-1" title="Amount received" readonly/>
                        <select name="country" class="select-country">
                            <option value="usa">미국</option>
                            <option value="china">중국</option>
                            <option value="thailand">태국</option>
                        </select>
                    </div>
                </div>
                <div class="row">
                    <div class="col-sm-4 off-4">
                        <div class="exchange-current">
                            <p>현재 환율 <span class="rate">0.00</span> 원 </p>
                        </div>

                    </div>
                    <div class="col-sm-4">
                    </div>
                </div>
            </div>
        </div>
    </section>
</div>

<script>
    function checkExchange() {
        let before = $('.before').val();
        let country = document.getElementsByName('country')
        let amount = document.getElementsByName('before').values()

        $('.rate').css("font-size", "11px");

        if (before.length == 0) {
            $('.rate').html("");
        } else {
            $.ajax({
                url: "<%=request.getContextPath()%>/rateCheck.do",
                type: "post",
                data: {
                    "country": country,
                    "amount": amount
                },
                success: function (result) {
                    $('.rate').html("result");
                },
                error: function () {
                    alert('error');
                }
            })
        }
    }
</script>



<!-- Scripts -->
<script src="${ pageContext.request.contextPath }/resources/js/jquery.min.js"></script>

</body>
</html>