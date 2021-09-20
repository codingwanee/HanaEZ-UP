<%@ page language="java" contentType="text/html; charset=UTF-8"
    pageEncoding="UTF-8"%>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>Title</title>
    <link href="/WEB-INF/resources/css/madecss.css" rel="stylesheet" type="text/css"/>
</head>
<body>
<!-- header -->

<!-- main -->
<div id="HANA_CONTENTS_DIV">
    <!-- ======= Breadcrumbs ======= -->
    <section id="breadcrumbs" class="breadcrumbs">
        <h2>하나은행 외국인 특화지점 이용하기</h2>
        <div class="locate">
            HOME &gt; 오프라인 지점 &gt; <strong>지점 예약하기</strong>
        </div>
    </section>
    <!-- End Breadcrumbs -->

    <!-- ======= Certificate Section ======= -->
    <section>
        <div class="container">
            <div class="reservation">

                <div class="reserve-date">
                    <div class="reserve-day"></div>
                    <div class="reserve-time"></div>
                </div>


            </div>
        </div>
    </section><!-- End Login Section -->
   <br><br><br><br>
</div>
<!-- footer -->


<!-- Modal -->
<div class="modal fade" id="loginModal" tabindex="-1" role="dialog" aria-labelledby="myModalLabel" aria-hidden="true">
    <div class="modal-dialog" role="document">
        <div class="modal-content">
            <div class="modal-header">
                <h5 class="modal-title" id="myModalLabel" contenteditable="true">회원만 이용 가능한 서비스입니다.</h5>
                <button type="button" class="close" data-dismiss="modal" aria-label="Close"><span aria-hidden="true">&times;</span>
                </button>
            </div>
            <div class="modal-body" contenteditable="true">
                로그인 한 회원만 이용할 수 있습니다. 로그인 하러 가시겠습니까?
            </div>
            <div class="modal-footer">
                <button type="button" class="btn btn-primary" contenteditable="true">로그인</button>
                <button type="button" class="btn btn-secondary" data-dismiss="modal" contenteditable="true">취소</button>
            </div>
        </div><!-- /.modal-content -->
    </div><!-- /.modal-dialog -->
</div><!-- /.modal -->
</body>
</html>