<%@ page language="java" contentType="text/html; charset=UTF-8"
	pageEncoding="UTF-8"%>
<%@ taglib uri="http://www.springframework.org/tags" prefix="spring"%>
<%@ taglib prefix="c" uri="http://java.sun.com/jsp/jstl/core"%>
<!DOCTYPE html>
<html>
<head>
<meta charset="utf-8">
<meta content="width=device-width, initial-scale=1.0" name="viewport">

<title>Welcome to HanaEZ UP</title>
<meta content="" name="descriptison">
<meta content="" name="keywords">
<script src="http://code.jquery.com/jquery-3.5.1.min.js"></script>

<!-- Favicons -->
<link
	href="${ pageContext.request.contextPath }/resources/assets/img/favicon.png"
	rel="icon">

<!-- Google Fonts -->
<link
	href="https://fonts.googleapis.com/css?family=Open+Sans:300,300i,400,400i,600,600i,700,700i|Raleway:300,300i,400,400i,600,600i,700,700i"
	rel="stylesheet">

<jsp:include page="/WEB-INF/views/home/include/common-css.jsp" />
<jsp:include page="/WEB-INF/views/admin/include/common-css.jsp" />

</head>

<body>

	<!-- ======= Header ======= -->
	<jsp:include page="/WEB-INF/views/home/include/header.jsp" />

	<!-- ======= Main ======= -->
	<div id="wrapper">
		<!-- ======= article Section ======= -->
		<section id="article" class="container">
			<div class="row">
				<div class="col-sm-12">
					<h2 class="page-title">
						<spring:message code="board.bread.title"></spring:message>
					</h2>
					<p class="card-text">
						<spring:message code="board.bread.text"></spring:message>
					</p>
					<div class="article-contentbox">
						<div class="container article-wrap">
							<div class="row article-header mg-sm-5">
								<div class="col-sm-8 article-title">
									<h4>${ boardVO.title }</h4>
									${ boardVO.writer }
								</div>
								<div class="col-sm-4 article-regDate">
									<span> <spring:message code="board.regDate"></spring:message>
										: ${ boardVO.regDate }<br> <spring:message
											code="board.viewCnt"></spring:message> : ${ boardVO.viewCnt }
										/ <spring:message code="board.cmtCnt"></spring:message> : ${ boardVO.cmtCnt }
									</span>
								</div>
							</div>
							<div class="row">
								<div class="col-sm-12 article-container">
									<div class="contentRenderer">${ boardVO.content }</div>
									<div class="comment-box">
										<div class="comment-title">
											<h5>
												<spring:message code="menu.comment"></spring:message>
											</h5>
										</div>
										<div id="commentList">
											<c:forEach items="${ commentList }" var="comment"
												varStatus="loop">
												<div class="comment-item">
													<div class="comment-writer">${ commentVO.writer }</div>
													<div class="comment-content">${ commentVO.content }</div>
													<div class="comment-info">
														<span class="comment-info-date">${ commentVO.regDate }</span>
														<a href="#" role="button" class="comment-info-button">
															<spring:message code="menu.comment"></spring:message>
														</a>
													</div>
												</div>
											</c:forEach>
										</div>
										<div class="row">
											<div class="col-sm-12 comment-editor">
											<form name="cForm">
<%-- 											action="${ pageContext.request.contextPath }/board/comment"> --%>
												<input type="hidden" name="writer" value="${loginVO.id}">
												<div class="comment-inbox">
													<textarea name="content"
														placeholder="<spring:message code="board.comment.text"></spring:message>"
														rows="1" class="comment-inbox-text"></textarea>
												</div>
												<div class="comment-btn">
													<input type="button" id="commentAddBtn"
														value="<spring:message code="register"></spring:message>"
														class="comment-submit" />
												</div>
												</form>
											</div>
										</div>
									</div>
								</div>
							</div>
							<div class="container">
								<div class="row justify-content-center align-items-center">
									<div class="col-sm-3 justify-content-center align-items-center">
										<c:if test="${ loginVO.id } eq ${ boardVO.writer }">
											<button class="btn btn-primary" onclick="btnClick('m')">
												<spring:message code="menu.edit"></spring:message>
											</button>
										</c:if>
									</div>
									<div class="col-sm-2 justify-content-center align-items-center">
										<button class="btn btn-outline-primary w-100"
											onclick="btnClick('l')">
											<spring:message code="menu.list"></spring:message>
										</button>
									</div>
									<div class="col-sm-2 justify-content-center align-items-center">
										<button class="btn btn-primary w-100" onclick="btnClick('r')">
											<spring:message code="menu.reply"></spring:message>
										</button>
									</div>
									<div class="col-sm-3 justify-content-center align-items-center">
										<c:if test="${ loginVO.id } == ${ boardVO.writer }">
											<button class="btn btn-secondary" onclick="btnClick('d')">
												<spring:message code="menu.delete"></spring:message>
											</button>
										</c:if>
									</div>
								</div>
							</div>
						</div>
					</div>
				</div>
			</div>
		</section>
	</div>
	<!-- ======= Footer ======= -->
	<footer>
		<%@include file="/WEB-INF/views/home/include/footer.jsp"%>
		<jsp:include page="/WEB-INF/views/home/include/common-js.jsp" />
	</footer>
	<!-- End Footer -->


	<script>
	function getcommentList() {
		// ?????????????????? ??????????????? ?????? => <div id="commentList"></div> ??????????????? ????????????
		$.ajax({
			url : '${ pageContext.request.contextPath }/board/comment/${ boardVO.num }',
			type : 'get',
			success : function(data) {
				
				$('#commentList').empty();
				
				let list = JSON.parse(data);
				
				$(list).each(function() {
				
					let str = '';
					str += '<hr>';
					str += '<div class="mb-3">';
					str += '<strong> ' + this.content + ' </strong>';
					str += '   (' + this.writer + ')   '
					str += '&nbsp;&nbsp;&nbsp;' + this.regDate + '&nbsp;&nbsp;&nbsp;'
					str += '<c:if test="'+ this.writer ' == ${loginVO.id}" >'
					str += '<button class="btn btn-default" id=' + this.no + '>??????</button>'
					str += '</c:if>'
					str += '</div>'
					
					$('#commentList').append(str);
				})
			}, 
			error : function() {
				alert('?????? ????????? ????????? ??????????????????.')
			}
		})
	}
	
	// ?????? ??????
	$(document).ready(function() {
		$('#commentAddBtn').click(function() {
			let content = document.cForm.content.value;
			let writer = document.cform.writer.value;
			
			// /comment/insert?boardNo=12&content=aaa&writer=bbb
			$.ajax({
				url : '${ pageContext.request.contextPath }/board/comment',
				type : 'post',
				data : {
					boardNum : ${ boardVO.num },
					content : content,
					writer : writer
				}, 
				success : function() {					
					getcommentList();
				}, 
				error : function() {
					alert('????????? ???????????? ???????????? ????????? ??????????????????.')
				},
				complete : function() {
					document.cform.writer.value = '';
					document.cform.content.value = '';
				}
			})
		})
	})
	
	$(document).ready(function() {
		getcommentList();
	})
	
	$(document).ready(function() {
		$(document).on('click', '.delBtn', function() {
			
			if(!confirm('????????? ?????????????????????????')) return;
			
			let commentNo = $(this).attr('id');
			
			$.ajax({
				url: '${ pageContext.request.contextPath }/board/comment/' + commentNo + '/${board.no}',
				type: 'delete',
				success : function() {
					getcommentList()
				}, error: function() {
					alert('??????')
				}
			});
			/*
			$.ajax({
				url: '${ pageContext.request.contextPath }/comment/' + commentNo,
				type: 'delete',
				success : function() {
					getcommentList()
				}, error: function() {
					alert('??????')
				}
			});
			*/
		})
	})
</script>
<script>
	function btnClick(type) {
		switch (type) {
		case 'm':
			location.href = "${ pageContext.request.contextPath }/board/modify";
			break;
		case 'd':
			if (confirm('?????????????????????????')) {
				location.href = "${ pageContext.request.contextPath }/board/delete/no=${ param.no }"; // EL ???????????? ???????????? ?????? ???????????? ??????.
			}
			break;
		case 'l':
			location.href = "${ pageContext.request.contextPath }/board"
			break;
		case 'r':
			location.href = "${ pageContext.request.contextPath }/board/reply"
		}
	}
</script>


</body>
</html>