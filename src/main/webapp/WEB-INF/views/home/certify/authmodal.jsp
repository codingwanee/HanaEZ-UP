<%@ page language="java" contentType="text/html; charset=UTF-8"
	pageEncoding="UTF-8"%>
<%@ taglib uri="http://www.springframework.org/tags" prefix="spring"%>


<!-- =========== 메일 인증 ============== -->
<div class="modal fade" id="authmail">
	<div class="modal-dialog">
		<div class="modal-content">
			<!-- header -->
			<div class="modal-header">
				<!-- header title -->
				<h4 class="modal-title">
					<spring:message code="certify.val.email"></spring:message>
				</h4>
				<!-- 닫기(x) 버튼 -->
				<button type="button" class="close" data-dismiss="modal">×</button>
			</div>
			<!-- body -->
			<div class="modal-body">
				<div class="container">
					<div class="row d-flex justify-content-center">
						<div class="row col-sm-12 input-group justify-content-center">
							<form action="${ pageContext.request.contextPath }/authmail/sending"
								method="post" class="form-inline">
								<div class="form-group">
									<div class="input-group">
										<input id="mailTo" type="email" name="mail" placeholder="이메일주소를 입력하세요."
											class="form-control" size=30>
									</div>
								</div>
								<button type="button" class="btn btn-outline-secondary" onclick="javascript:sendAuthMail(); return false;">전송</button>
							</form>


<%-- 							<form action="${ pageContext.request.contextPath }/authmail/validation/${authCode}" --%>
							<form class="form-inline">
								<div class="form-group">
									<div class="input-group">
										<input type="text" id="authMail-input" name="inputCode" class="form-control"
											placeholder="인증번호를 입력하세요."  size=30>
									</div>
								</div>
								<button type="button" class="btn btn-outline-secondary"
									onclick="javascript: valMail(); return false;">인증</button>
							</form>
							
						</div>
					</div>

				</div>
				<!-- /.row -->
			</div>
			<!-- /.container -->
		</div>
<!-- 		<!-- Footer -->
		<div class="modal-footer">
			<button type="button" class="btn btn-default" data-dismiss="modal">닫기
			</button>
		</div> -->
	</div>
</div>


<!-- =========== 문자 인증 ============== -->
<div class="modal fade" id="authsms">
	<div class="modal-dialog">
		<div class="modal-content">
			<!-- header -->
			<div class="modal-header">
				<!-- header title -->
				<h4 class="modal-title">
					<spring:message code="certify.val.sms"></spring:message>
				</h4>
				<!-- 닫기(x) 버튼 -->
				<button type="button" class="close" data-dismiss="modal">×</button>
			</div>
			<!-- body -->
			<div class="modal-body">
				<div class="container">
					<div class="row d-flex justify-content-center">
						<div class="row col-sm-12 input-group justify-content-center">
							<form action="${ pageContext.request.contextPath }/sms/sending"
								method="post" class="form-inline">
								<div class="form-group">
									<div class="input-group">
										<input type="text" id="smsTo" name="smsTo" placeholder="전화번호 입력" class="form-control" size=30>
									</div>
								</div>
								<button type="button" class="btn btn-outline-secondary"
								onclick="javascript:sendAuthSms(); return false;">전송</button>
<!-- 								<button type="submit" class="btn btn-outline-secondary">전송</button> -->
							</form>
							<form action="${ pageContext.request.contextPath }/authsms/validation/${authCode}"
								method="post" class="form-inline">
								<div class="form-group">
									<div class="input-group">
										<input type="text" id="authSms-input" name="inputCode" class="form-control"
											placeholder="인증번호를 입력하세요." size=30>
									</div>
								</div>
								<button type="button" class="btn btn-outline-secondary"
								onclick="javascript:valSms(); return false;" data-dismiss="modal">인증</button>
							</form>
						</div>
					</div>
				</div>
				<!-- /.row -->
			</div>
			<!-- /.container -->
		</div>
		<!-- Footer -->
<!-- 		<div class="modal-footer">
			<button type="button" class="btn btn-default" data-dismiss="modal">닫기</button>
		</div> -->
	</div>
</div>




<!-- =========== 인증성공 ============== -->
<div class="modal fade" id="auth-completed">
	<div class="modal-dialog">
		<div class="modal-content">
			<!-- header -->
			<div class="modal-header">
				<!-- header title -->
				<h4 class="modal-title">
					<spring:message code="mail.modal.successtitle"></spring:message>
				</h4>
				<!-- 닫기(x) 버튼 -->
				<button type="button" class="close" data-dismiss="modal">×</button>
			</div>
			<!-- body -->
			<div class="modal-body">
				<div class="container">
					<div class="row align-items-center h-100">
						<form class="col-lg-12 col-md-12 col-10 mx-auto text-center">
							<div class="mx-auto text-center my-4">
								<h4 class="my-3">
									<spring:message code="mail.modal.successmsg"></spring:message>
								</h4>
							</div>
							<div class="alert alert-success" role="alert">
								<spring:message code="mail.modal.successtext"></spring:message>
							</div>
						</form>
						<button type="button" class="btn btn-lg btn-secondary btn-block"
							data-dismiss="modal"
							onclick="location.href='${ pageContext.request.contextPath }/certify'">
							<spring:message code="mail.modal.closebtn"></spring:message>
						</button>
						<p class="mt-5 mb-3 text-muted">© Hyewon Jeon</p>
					</div>
				</div>
				<!-- /.row -->
			</div>
			<!-- /.container -->
		</div>
		<!-- Footer -->
		<div class="modal-footer">
			<button type="button" class="btn btn-default" data-dismiss="modal">다음 단계로 넘어가기</button>
		</div>
	</div>
</div>




<script>
 let authCode;
 let inputCode;
	
	function sendAuthMail() {
	 	let mailTo = $('#mailTo').val();	 	
	 	
	 	mailTo = mailTo + '.dummy'
	 	console.log('in javascript mailTo : ' + mailTo)
	 	
		$.ajax({
			url: '${ pageContext.request.contextPath }/authmail/sending/' + mailTo,
			type : 'get',
			success: function(data) {
				$('#mailTo').empty();
 				authCode = data;
 	/*			authCode = authCode.substring(1, authCode.length -1)	  */		 
			},
			error : function() {
				alert('<spring:message code="error.common"></spring:message>')
			}
		}) 
	}
 
	
	function sendAuthSms() {
	 	let smsTo = $('#smsTo').val();
	 
		$.ajax({
			url: '${ pageContext.request.contextPath }/sms/sending/' + smsTo,
			type : 'get',
			success: function(data) {
				console.log(data)
				$('#smsTo').empty();
				authCode = data;
				authCode = authCode.substring(1, authCode.length -1)			
			},
			error : function() {
				alert('<spring:message code="error.common"></spring:message>')
			}
		})
	}
	
	function valMail() {
		inputCode = $('#authMail-input').val();		
		if(authCode == inputCode) {	
			nextPrev(1)		
		} else {
			alert('일시적인 오류가 발생했습니다.')
		}
	}
	
	function valSms() {
		
		inputCode = $('#authSms-input').val();		
		if(authCode == inputCode) {	
			nextPrev(1)			
		} else {
			alert('일시적인 오류가 발생했습니다.')
		}
	}

</script>