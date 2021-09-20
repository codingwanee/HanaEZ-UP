<%@ page language="java" contentType="text/html; charset=UTF-8"
	pageEncoding="UTF-8"%>
<%@ taglib uri="http://java.sun.com/jsp/jstl/core" prefix="c"%>
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
<style>
label {
	color: #495057;
}
</style>

</head>
<body>
	<!-- ======= Header ======= -->
	<jsp:include page="/WEB-INF/views/home/include/header.jsp" />


	<!-- ======= Main ======= -->
	<div id="wrapper">
		<!-- ======= Board Write Section ======= -->
		<section id="write" class="container">
			<div class="row">
				<div class="col-sm-12">
					<h2 class="page-title">통역사 지원서</h2>
					<p class="card-text">
						자신있는 언어가 있다면, 하나은행의 통역사로 지원해주세요! 검토 후 연락을 드리도록 하겠습니다.
					</p>
					<div class="row mb-4">
						<div class="col-md-10">
							<div class="card shadow">
								<div class="card-body p-5">
									<!--
									<div class="card-header">
									 	<strong class="card-title">통역사 인력풀 등록 양식</strong>
									</div>
									-->
									<h5 class="card-title">한국인 여부</h5>
									<form
										action="${ pageContext.request.contextPath }/translator/register" method="post"
										class="needs-validation" novalidate>
										<label for="validationCustom01">본인의 모국어를 선택하세요. Select
											your mother language.</label>
										<div class="custom-control custom-radio">
											<input type="radio" class="custom-control-input" value="ko"
												id="customControlValidation2" name="motherLang" required>
											<label class="custom-control-label"
												for="customControlValidation2">한국어 Korean</label>
										</div>
										<div class="custom-control custom-radio mb-3">
											<input type="radio" class="custom-control-input" value="for"
												id="customControlValidation3" name="motherLang" required>
											<label class="custom-control-label"
												for="customControlValidation3">외국어 Non-Korean</label>
										</div>
										<hr class="mt-5 mb-4">
										<h5 class="card-title">기본 신상정보</h5>
										<div class="form-row">
											<div class="col-md-6 mb-3">
												<label for="validationCustom01">이름 First Name</label> <input
													type="text" class="form-control" id="validationCustom01"
													name="firstName" value="" required>
											</div>
											<div class="col-md-6 mb-3">
												<label for="validationCustom02">성 Last name</label> <input
													type="text" class="form-control" name="lastName"
													id="validationCustom02" value="" required>
											</div>
											<div class="col-md-4 mb-3">
												<label for="validationCustom04">전화번호 Phone Number</label>
												<select class="form-control" id="tel1" name="tel1" required>
													<option selected disabled>Choose...</option>
													<option value="010">010</option>
													<option value="011">011</option>
													<option value="017">017</option>
												</select>
											</div>
											<div class="col-md-4 mb-3">
												<label for="validationCustom03">&nbsp;</label> <input
													type="text" class="form-control" id="tel2" name="tel2"
													required>
											</div>
											<div class="col-md-4 mb-3">
												<label for="validationCustom05">&nbsp;</label> <input
													type="text" class="form-control" id="tel3" name="tel3"
													required>
											</div>
											<div class="col-md-6 mb-1">
												<label for="validationCustomUsername">이메일 Email</label>
												<div class="input-group">
													<!--
													<div class="input-group-prepend">
															<span class="input-group-text" id="inputGroupPrepend">@</span>
													</div>
													-->
													<input type="text" class="form-control" name="email"
														id="validationCustomUsername"
														aria-describedby="inputGroupPrepend" required>
												</div>
											</div>


											<div class="col-md-6 mb-3">
												<label for="validationCustom04">희망근무 지점</label> <select
													class="custom-select" name="branch" required>
													<option selected disabled value="">Choose...</option>

													<c:forEach items="${ branchList }" var="branchVO">
														<option value="${ branchVO.bid }">${ branchVO.nameKo }
															/ ${ branchVO.nameEn }</option>
													</c:forEach>
												</select>
											</div>

											<div class="col-md-12 mb-3">
												<small id="emailHelp" class="form-text text-muted">작성해주신
													연락처는 외부에 공개되지 않습니다. We'll never share your contacts with
													anyone else.
												</small>
											</div>
											<div class="col-md-3 mb-3"></div>
										</div>

										<hr class="mt-5 mb-4">
										<h5 class="card-title">언어 선택</h5>
										<div class="form-row">
											<div class="col-md-6 mb-3">
												<div class="form-group mb-4">
													<label for="example-multiselect">지원하는 언어 Choose
														Language</label> <select class="custom-select"
														id="validationCustom04" name="lang" required>
														<option selected disabled value="">Choose...</option>
														<option value="en">English</option>
														<option value="ch">中文</option>
														<option value="th">ประเทศไทย</option>
														<option value="sr">සිංගලා</option>
														<option value="my">Myanmar</option>
														<option value="vn">Người việt nam</option>
														<option value="ph">Pilipinas</option>
														<option value="mg">Монгол</option>
														<option value="id">Indonesia</option>
														<option value="cb">Cambodian</option>
														<option value="jp">日本語</option>
														<option value="bg">नेपाल</option>
														<option value="np">កម្ពុជា</option>
														<option value="rs">Россия</option>
														<option value="uz">O'zbekiston</option>
														<!-- 
														<option value="en">English</option>
														<option value="ch">Chinese</option>
														<option value="th">Thai</option>
														<option value="sr">Sri Lankan</option>
														<option value="my">Burnese</option>
														<option value="vn">Vietnamese</option>
														<option value="ph">Philippines</option>
														<option value="mg">Mongolian</option>
														<option value="id">Indonesia</option>
														<option value="cb">Cambodian</option>
														<option value="jp">Japanese</option>
														<option value="bg">Bangladesh</option>
														<option value="np">Nepali</option>
														<option value="rs">Russian</option>
														<option value="uz">Uzbekistan</option>
														-->
													</select>
												</div>
											</div>

											<div class="col-md-6 mb-3">
												<label for="validationCustom04">언어레벨 선택 Choose Level</label>
												<select class="custom-select" id="validationCustom04"
													name="langLv" required>
													<option selected disabled value="">Choose...</option>
													<option value="1">Level 1 (Low Intermediate)</option>
													<option value="2">Level 2 (Intermediate)</option>
													<option value="3">Level 3 (Upper-Intermediate)</option>
													<option value="4">Level 4 (Pre-Advanced)</option>
													<option value="5">Level 5 (Advanced)</option>
													<option value="6">Level 6 (Proficiency)</option>
												</select>
											</div>
										</div>
										<hr class="mt-5 mb-4">
										<div class="form-group mb-5">
											<h5 class="card-title">자기소개말 Express yourself</h5>
											<textarea class="form-control" id="validationTextarea"	name="message"
												placeholder="자신에 대한 소개말을 적어주세요. Express anything about yourself." required></textarea>
										</div>
										<!--
 										<div class="custom-file mb-3">
											<label for="validationTextarea">자신을 나타내는 사진을 한 장
												등록해주세요.</label><input type="file" class="custom-file-input"
												id="validatedCustomFile" required> <label
												class="custom-file-label" for="validatedCustomFile">Choose
												file...</label>
											<div class="invalid-feedback">Example invalid custom
												file feedback</div>
										</div>
-->
										<div class="row">
										<div class="col-sm-9">
											<div class="custom-control custom-checkbox mb-3">
												<input type="checkbox" class="custom-control-input"
													id="customControlValidation1" required> <label
													class="custom-control-label" for="customControlValidation1">개인정보
													수집, 이름 및 제공 조회하는 데 동의합니다.</label>
												<button type="button" class="btn btn-outline-default" style="margin-top: -7px; border: 1px solid #dee2e6;"
													data-toggle="modal" data-target="#privacy">내용확인</button>
											</div>
										</div>
										<div class="col-sm-3 align-right">
											<button class="btn btn-primary" type="submit" style="margin-top: -7px;">제출하기</button>
										</div>
										</div>
									</form>
								</div>
							</div>
						</div>
					</div>
				</div>
			</div>
		</section>
	</div>
	<script>
      $('.select2').select2(
      {
        theme: 'bootstrap4',
      });
      $('.select2-multi').select2(
      {
        multiple: true,
        theme: 'bootstrap4',
      });
      $('.drgpicker').daterangepicker(
      {
        singleDatePicker: true,
        timePicker: false,
        showDropdowns: true,
        locale:
        {
          format: 'MM/DD/YYYY'
        }
      });
      $('.time-input').timepicker(
      {
        'scrollDefault': 'now',
        'zindex': '9999' /* fix modal open */
      });
      /** date range picker */
      if ($('.datetimes').length)
      {
        $('.datetimes').daterangepicker(
        {
          timePicker: true,
          startDate: moment().startOf('hour'),
          endDate: moment().startOf('hour').add(32, 'hour'),
          locale:
          {
            format: 'M/DD hh:mm A'
          }
        });
      }
      var start = moment().subtract(29, 'days');
      var end = moment();

      function cb(start, end)
      {
        $('#reportrange span').html(start.format('MMMM D, YYYY') + ' - ' + end.format('MMMM D, YYYY'));
      }
      $('#reportrange').daterangepicker(
      {
        startDate: start,
        endDate: end,
        ranges:
        {
          'Today': [moment(), moment()],
          'Yesterday': [moment().subtract(1, 'days'), moment().subtract(1, 'days')],
          'Last 7 Days': [moment().subtract(6, 'days'), moment()],
          'Last 30 Days': [moment().subtract(29, 'days'), moment()],
          'This Month': [moment().startOf('month'), moment().endOf('month')],
          'Last Month': [moment().subtract(1, 'month').startOf('month'), moment().subtract(1, 'month').endOf('month')]
        }
      }, cb);
      cb(start, end);
      $('.input-placeholder').mask("00/00/0000",
      {
        placeholder: "__/__/____"
      });
      $('.input-zip').mask('00000-000',
      {
        placeholder: "____-___"
      });
      $('.input-money').mask("#.##0,00",
      {
        reverse: true
      });
      $('.input-phoneus').mask('(000) 000-0000');
      $('.input-mixed').mask('AAA 000-S0S');
      $('.input-ip').mask('0ZZ.0ZZ.0ZZ.0ZZ',
      {
        translation:
        {
          'Z':
          {
            pattern: /[0-9]/,
            optional: true
          }
        },
        placeholder: "___.___.___.___"
      });
      // editor
      var editor = document.getElementById('editor');
      if (editor)
      {
        var toolbarOptions = [
          [
          {
            'font': []
          }],
          [
          {
            'header': [1, 2, 3, 4, 5, 6, false]
          }],
          ['bold', 'italic', 'underline', 'strike'],
          ['blockquote', 'code-block'],
          [
          {
            'header': 1
          },
          {
            'header': 2
          }],
          [
          {
            'list': 'ordered'
          },
          {
            'list': 'bullet'
          }],
          [
          {
            'script': 'sub'
          },
          {
            'script': 'super'
          }],
          [
          {
            'indent': '-1'
          },
          {
            'indent': '+1'
          }], // outdent/indent
          [
          {
            'direction': 'rtl'
          }], // text direction
          [
          {
            'color': []
          },
          {
            'background': []
          }], // dropdown with defaults from theme
          [
          {
            'align': []
          }],
          ['clean'] // remove formatting button
        ];
        var quill = new Quill(editor,
        {
          modules:
          {
            toolbar: toolbarOptions
          },
          theme: 'snow'
        });
      }
      // Example starter JavaScript for disabling form submissions if there are invalid fields
      (function()
      {
        'use strict';
        window.addEventListener('load', function()
        {
          // Fetch all the forms we want to apply custom Bootstrap validation styles to
          var forms = document.getElementsByClassName('needs-validation');
          // Loop over them and prevent submission
          var validation = Array.prototype.filter.call(forms, function(form)
          {
            form.addEventListener('submit', function(event)
            {
              if (form.checkValidity() === false)
              {
                event.preventDefault();
                event.stopPropagation();
              }
              form.classList.add('was-validated');
            }, false);
          });
        }, false);
      })();
    </script>
	<script>
      var uptarg = document.getElementById('drag-drop-area');
      if (uptarg)
      {
        var uppy = Uppy.Core().use(Uppy.Dashboard,
        {
          inline: true,
          target: uptarg,
          proudlyDisplayPoweredByUppy: false,
          theme: 'dark',
          width: 770,
          height: 210,
          plugins: ['Webcam']
        }).use(Uppy.Tus,
        {
          endpoint: 'https://master.tus.io/files/'
        });
        uppy.on('complete', (result) =>
        {
          console.log('Upload complete! We’ve uploaded these files:', result.successful)
        });
      }
    </script>

	<!-- ======= Footer ======= -->
	<%@include file="/WEB-INF/views/home/include/footer.jsp"%>
	<jsp:include page="/WEB-INF/views/home/include/common-js.jsp" />
	<!-- End Footer -->

	<!-- Modal -->
	<div class="modal fade" id="privacy" tabindex="-1" role="dialog"
		aria-labelledby="exampleModalLongTitle" aria-hidden="true">
		<div class="modal-dialog modal-lg" role="document">
			<div class="modal-content">
				<div class="modal-header">
					<h5 class="modal-title" id="exampleModalLongTitle">개인정보 이용방침</h5>
					<button type="button" class="close" data-dismiss="modal"
						aria-label="Close">
						<span aria-hidden="true">&times;</span>
					</button>
				</div>
				<div class="modal-body p-4">
					<div id="contents" class="hana-contents p-3">
						<h4 class="infoDealing04">개인정보처리방침</h4>
						<p>
							하나은행(이하 “당행”이라 합니다)은 개인정보보호법 제30조에 따라 고객의 개인정보 및 권익을 보호하고 개인정보와
							관련한 고객의 고충을 원활하게 처리할 수 있도록 다음과 같은 처리방침을 두고 있습니다.
						</p>
						<h5 class="tabTit">제1조(개인정보의 처리 목적)</h5>
						<p class="contP">
							당행은 개인정보를 다음 각 호의 목적을 위해 처리합니다. 수집된 개인정보는 다음의 목적 외의 용도로는 사용되지 않으며
							이용 목적이 변경될 시에는 사전동의를 구할 예정입니다.
						</p>
						<h6 class="tabTit">1. (금융)거래 관계 관련</h6>
						<p class="contP">
							(금융)거래와 관련하여 신용정보회사 또는 신용정보집중기관에 대한 개인신용정보의 조회, (금융)거래 관계의 설정 여부의
							판단,(금융)거래 관계의 설정·유지·이행·관리, 금융사고 조사, 분쟁 해결, 민원 처리 및 법령상
							의무이행 등의 목적으로 개인정보를 처리합니다.
						</p>
						<p class="contP">
							※ (금융)거래라 함은 은행업무(여신, 수신, 내·외국환), 겸영업무(펀드, 신탁, 파생상품, 방카슈랑스, 신용카드
							등) 및 <span style="padding-left: 16px;">부수업무(팩토링,
								보호예수, 수납 및 지급대행, 대여금고, 상품권 등 판매대행 등)와 이와 관련된 거래를 의미합니다.</span>
						</p>
						<h6 class="tabTit">2. 상품 및 서비스 홍보 및 판매 권유</h6>
						<p class="contP">
							고객 만족도 조사를 통한 신규 서비스 개발 및 맞춤 서비스 제공, 인구통계학적 특성에 따른 서비스 제공 및 광고의
							게재, 서비스의 유효성 확인,경품지급, 사은행사 등 고객의 편의 및 참여기회 제공, 접속빈도 파악,
							회원의 서비스이용에 대한 통계 등의 목적으로 개인정보를 처리합니다.
						</p>
						<h6 class="tabTit">3. 회원 가입 및 관리</h6>
						<p class="contP">
							회원가입, 회원제 서비스 이용, 제한적 본인 확인제에 따른 본인확인, 개인식별, 부정이용방지, 비인가 사용방지,
							가입의사 확인, 만14세 미만 아동 개인정보 수집 시 법정대리인 동의여부 확인, 추후 법정 대리인
							본인확인, 사고조사, 분쟁해결, 민원처리 및고지사항 전달 등의 목적으로 개인정보를 처리합니다.
						</p>
						<h6 class="tabTit">4. 온라인 거래 관련 목적</h6>
						<p class="contP">
							전자금융거래법 제21조, 제22조에 의해 전자금융거래의 내용 추적 및 검색, 보안정책 수립용 통계 자료로 활용 등을
							목적으로 개인정보를처리합니다.
						</p>
						<h5 class="tabTit">제2조(개인정보의 처리 및 보유 기간)</h5>
						<ol class="orderListNum">
							<li>(금융)거래와 관련한 개인(신용)정보는 수집·이용에 관한 동의일로부터 (금융)거래 종료일로부터
								5년까지 위 이용목적을 위하여 보유·이용됩니다.단, (금융)거래 종료일 이후에는 금융사고 조사,
								분쟁 해결, 민원처리, 법령상 의무이행 및 당행의 리스크 관리업무만을 위하여 보유·이용됩니다.
							</li>
							<li>개인(신용)정보의 조회를 목적으로 수집된 개인(신용)정보는 수집·이용에 대한 동의일로부터 고객에 대한
								신용정보 제공·조회 동의의 효력 기간까지 보유·이용됩니다.단, 신용정보 제공ㆍ조회
								동의의 효력 기간 종료 후에는 금융사고 조사, 분쟁 해결, 민원처리 및 법령상 의무이행만을 위하여 보유·이용됩니다.
							</li>
							<li>상품 및 서비스 홍보 및 판매 권유 등과 관련한 개인(신용)정보는 수집·이용에 관한 동의일로부터 동의
								철회일까지 보유·이용됩니다.단, 동의 철회일 후에는 제1조의 목적과 관련된 사고 조사, 분쟁 해결,
								민원처리, 법령상 의무이행만을 위하여 보유·이용됩니다.
							</li>
							<li>회원 가입 및 관리 목적으로 수집된 개인(신용)정보는 고객의 회원 가입일로부터 회원 탈퇴일까지
								보유·이용됩니다.단 회원 탈퇴일 후에는 제1조의 목적과 관련된 사고 조사, 분쟁 해결, 민원처리,
								법령상 의무이행 만을 위하여 보유·이용됩니다.
							</li>
							<li>온라인 거래 관련한 개인(신용)정보는 전자금융거래법 시행령 제12조에서 정하는 기간까지
								보유·이용됩니다.</li>
						</ol>
						<h5 class="tabTit">제3조(개인정보 수집 출처 등 고지)</h5>
						<ol class="orderListNum">
							<li>당행은 정보주체 이외로부터 수집한 개인정보를 처리하는 때에는 정당한 사유가 없는 한 정보주체의 요구가
								있은 날로부터 3영업일 이내에수집 출처, 처리 목적, 개인정보 처리의 정지를 요구할 권리가 있다는
								사실을 정보주체에게 알립니다.
							</li>
							<li>개인정보 보호법 제20조제4항 각 호에 근거하여 제1항에 따른 정보주체의 요구를 거부하는 경우에는,
								정당한 사유가 없는 한 정보주체의 요구가 있은 날로부터 3영업일 이내에 그 거부의 근거와 사유를
								정보주체에게 알립니다.
							</li>
						</ol>
						<h5 class="tabTit">제4조(개인정보의 제3자 제공)</h5>
						<ol class="orderListNum">
							<li>당행은 원칙적으로 고객의 개인정보를 제1조에서 명시한 목적 범위 내에서 처리하며, 고객의 사전 동의
								없이는 본래의 범위를 초과하여 처리하거나 제3자에게 제공하지 않습니다. 단, 다음의 각 호의
								경우에는 고객 또는 제3자의 이익을 부당하게 침해할 우려가 있을 때를 제외하고는 개인정보를 목적
								외의 용도로 이용하거나 이를 제3자에게 제공할 수 있습니다.
								<ol class="orderListDecimal ml20">
									<li>고객이 사전에 제3자 제공 및 공개에 동의한 경우</li>
									<li>다른 법률에 특별한 규정이 있는 경우</li>
									<li>고객 또는 그 법정대리인이 의사표시를 할 수 없는 상태에 있거나 주소불명 등으로 사전 동의를 받을
										수 없는 경우로서 명백히 고객 또는 <span style="padding-left: 16px;">제3자의
											급박한 생명, 신체, 재산의 이익을 위하여 필요하다고 인정되는 경우</span>
									</li>
								</ol>
							</li>
							<li>당행은 다음 각호와 같이 개인정보를 제공하고 있습니다.
								<ol class="orderListDecimal ml20">
									<li>신용정보집중기관*, 신용정보회사*  ∙ 이용목적 - 금융기관에
										대한 신용정보를 집중 수입, 보관, 제공  - 신용을 판단하기 위한 자료로 활용하거나
										공공기관에서 정책자료로 활용 - 기타 동법 및 다른 법률의 규정에서 정한 사항 
										∙ 제공하는 신용정보의 종류  - 개인식별정보, 신용거래정보, 신용능력정보, 신용도판단정보,
										기타 신용평가를 위한 정보  * 신용정보집중기관 : 한국신용정보원* 신용정보회사
										: 서울신용평가정보㈜, 코리아크레딧뷰로(주), 나이스평가정보㈜, 한국기업데이터㈜, 나이스디앤비㈜, ㈜이크레더블
										등
									</li>
									<li>제휴업체- 홈페이지&gt;고객센터&gt;개인정보처리방침&gt;개인(신용)정보처리
										위탁 및 제공 현황에서 확인 가능
									</li>
								</ol>
							</li>
							<li>개인(신용)정보는 제공된 날로부터 동의 철회 시 또는 제공된 목적을 달성할 때까지 보유·이용됩니다.
								동의 철회 또는 제공된 목적 달성 후에는위에 기재된 이용목적과 관련된 금융사고 조사, 분쟁해결,
								민원처리, 법령상 의무이행을 위하여 필요한 범위 내에서만 보유·이용됩니다.
							</li>
						</ol>
						<h5 class="tabTit">제5조(개인정보처리 위탁)</h5>
						<ol class="orderListNum">
							<li>당행은 처리목적 달성을 위하여 개인정보의 처리를 위탁하고 있으며,자세한 내용은
								“홈페이지 &gt; 고객센터 &gt; 개인정보처리방침 &gt; 개인(신용)정보처리 위탁 및 제공 현황”에서 확인할
								수 있습니다.
							</li>
							<li>위탁계약 체결 시 개인정보보호 관련 법규의 준수, 개인정보에 관한 제3자 제공 금지 및 책임부담 등을
								명확히 규정하고,당해 계약내용을 서면 및 전자 보관하고 있습니다.
							</li>
							<h5 class="tabTit">제6조(고객의 권리·의무 및 그 행사방법)</h5>
							<ol class="orderListNum">
								<li>고객은 당행이 처리하는 자신 및 14세 미만 아동(법정대리인만 해당)의 열람을 요구할 수 있습니다.</li>
								<li>자신의 개인정보를 열람한 고객은 사실과 다르거나 확인할 수 없는 개인정보에 대하여 당행에 정정 또는
									삭제를 요구할 수 있습니다.다만, 다른 법령에서 그 개인정보가 수집 대상으로 명시되어 있는
									경우에는 그 삭제를 요구할 수 없습니다.
								</li>
								<li>고객은 당행에 대하여 자신의 개인정보 처리의 정지를 요구할 수 있습니다. 다만 다음 각 호의 어느
									하나에 해당하는 경우에는 당행은 해당 사유를 고객에게 알리고, 처리정지 요구를 거절할 수
									있습니다.
								</li>
								<ol class="orderListDecimal ml20">
									<li>법률에 특별한 규정이 있거나 법령상 의무를 준수하기 위하여 불가피한 경우</li>
									<li>다른 사람의 생명ㆍ신체를 해할 우려가 있거나 다른 사람의 재산과 그 밖의 이익을 부당하게 침해할
										우려가 있는 경우</li>
									<li>개인정보를 처리하지 아니하면 고객과 약정한 서비스를 제공하지 못하는 등 계약의 이행이 곤란한
										경우로서 고객이 그 계약의 해지 의사를 <span
										style="padding-left: 16px;"> 명확하게 밝히지 아니한 경우</span>
									</li>
								</ol>
							</ol>
							<h5 class="tabTit">제7조(처리하는 개인정보의 항목)</h5>
							<p class="contP">당행은 (금융)거래의 설정·유지·이행·관리 및 상품서비스의 제공을 위한 필수정보
								및 선택정보를 다음 각 호와 같이 수집하고 있습니다.</p>
							<h6 class="tabTit">필수적 정보</h6>
							<ul class="orderListDot">
								<li>개인식별정보 : 성명, 주민등록번호 등 고유식별정보, 국적, 직업군, 주소, 전화번호 등 연락처,
									바이오인증정보, 전자우편주소</li>
								<li>(금융)거래정보 : 상품종류, 거래조건(이자율, 만기, 담보 등), 거래일시, 금액 등 거래 설정
									및 내역 정보</li>
								<li>신용평가를 위한 정보(여신거래에 한함)
									<ul class="orderListDash">
										<li>신용능력정보 : 직업·재산·채무·소득의 총액 및 납세실적, 그 밖에 이와 유사한 정보</li>
										<li>신용도판단정보 : 금융거래 등 상거래와 관련하여 발생한 채무의 불이행, 연체, 부도, 대위변제,
											대지급과 그 밖의 부정한 방법에 의한 신용질서 <span
											style="padding-left: 9px;">문란행위와 관련된 금액 및 발생, 해소의 시기
												등에 관한 사항</span>
										</li>
									</ul>
								</li>
								<li>전자금융거래법에 따른 정보 : 사용자ID, 접속일시, IP주소 또는 전화번호 등 전자금융거래법에
									따른 수집 정보</li>
								<li>기타 금융거래의 설정·유지·이행·관리를 위한 상담, 채권관리 등을 통해 생성되는 정보</li>
							</ul>
							<h6 class="tabTit">선택적 정보</h6>
							<ul class="orderListDot">
								<li>개인식별정보 외에 거래신청서에 기재된 정보 또는 고객이 제공한 정보
									<ul class="orderListDash">
										<li>주거 및 가족사항, 거주기간, 세대구성, 결혼여부</li>
									</ul>
								</li>
							</ul>
							<h6 class="tabTit">인터넷 접속파일 등 개인정보 자동 수집 장치의 설치·운영 및 거부에 관한
								사항</h6>
							<p class="contP">당행은 손님 개개인에게 개인화되고 맞춤화된 서비스를 제공하기 위해 다음의 각호와
								같은 인터넷 접속정보파일 등 자동 수집 장치를 설치·운영하고 있습니다.</p>
							<ul class="orderListDot">
								<li>쿠키(cookie) 당행은 손님의 정보를 수시로 저장하고 찾아내는
									'쿠키(cookie)' 등을 운용합니다. 쿠키란 당행의 웹사이트를 운영하는데 이용되는 서버가 손님의 브라우저에
									보내는 아주 작은 텍스트 파일로서 손님의 컴퓨터 하드디스크에 저장됩니다. 당행은 다음과 같은 목적을 위해 쿠키를
									사용합니다.
									<ul class="orderListDash">
										<li>쿠키 등 수집항목, 보유기간 및 사용 목적</li>
									</ul>
									<p class="contP">쿠키 등의 접속화면, 접속빈도, 접속시간을 수집하며 아래 목적을 위하여
										금융거래 종료시까지 보유이용합니다.</p>
									<p class="contP">회원과 비회원의 접속 빈도나 방문 시간 등을 분석, 자취추적, 각종 이벤트
										참여 정도 및 방문 회수 파악 등을 통한 맞춤 서비스 제공 및 사용성 개선</p>
									<p class="contP">손님은 쿠키 설치에 대한 선택권을 가지고 있습니다. 따라서, 손님은
										웹브라우저에서 옵션을 설정함으로써 모든 쿠키를 허용하거나, 쿠키가 저장될 때마다 확인을 거치거나, 아니면 모든
										쿠키의 저장을 거부할 수도 있습니다.</p>
									<ul class="orderListDash">
										<li>쿠키 설정 거부 방법</li>
									</ul>
									<p class="contP">쿠키 설정을 거부하는 방법으로는 회원님이 사용하시는 웹 브라우저의 옵션을
										선택함으로써 모든 쿠키를 허용하거나 쿠키를 저장할 때마다 확인을 거치거나, 모든 쿠키의 저장을 거부할 수
										있습니다.</p>
									<p class="contP">설정방법 예(인터넷 익스플로어의 경우) : 웹 브라우저 상단의 도구 &gt;
										인터넷 옵션 &gt; 개인정보</p>
									<p class="contP">단, 귀하께서 쿠키 설치를 거부하였을 경우 서비스 제공에 어려움이 있을 수
										있습니다.</p></li>
								<li>페이스북 픽셀 당행은 이용자의 광고 효과를 분석하기 위해, 페이스북의 1x1 픽셀의
									코드를 개인뱅킹 채널, 스마트폰 앱, 모바일웹뱅킹 내에 설치합니다.
									<ul class="orderListDash">
										<li>수집 정보: 각 사용자의 이벤트 시간(Event Time), 이벤트 카테고리(Event
											Category), 기기(Device), 추천 URL(Referring URL)</li>
										<li>거부방법: 페이스북 계정 로그인 &gt; 설정 &gt; 광고 &gt; 광고설정에서 ‘허용되지
											않음’ 설정, 웹브라우저, 스마트폰 등의 쿠키 차단 설정</li>
									</ul></li>
							</ul>
							<h6 class="tabTit">전자금융거래법에 따른 수집정보</h6>
							<p class="contP">당행은 전자금융거래법의 이행을 위해 자동수집장치를 운영합니다.</p>
							<ul class="orderListDash">
								<li>수집정보: 고객 아이디, 접속일시, IP주소 또는 전화번호, 전자적 장치와 접근매체 관련
									정보(HDD Serial, MAC Address, 개인방화벽 설정, <span
									style="padding-left: 9px;">운영체제 종류 브라우저 버전 등), 전자금융거래 내용
										등</span>
								</li>
								<li>별도의 거절절차는 없음</li>
							</ul>
							<h6 class="tabTit">전화상담 업무 과정에서 자동 수집되는 정보</h6>
							<p class="contP">당행은 전화상담업무 처리과정에서 다음의 정보를 자동수집합니다.</p>
							<ul class="orderListDash">
								<li>콜센터금융부의 대고객 업무 과정에서 생성되는 정보</li>
								<li>금융소비자보호부의 민원업무 과정에서 생성되는 정보</li>
								<li>영업점에서 자산관리 또는 대출자동연장 업무 과정에서 생성되는 정보</li>
								<li>별도의 거절절차는 없으며 전화상담 거부시 자동 수집되지 않음</li>
							</ul>
							<p class="contP">
								※ 당행은 원칙적으로 고객의 사생활을 침해할 우려가 있는 민감정보는 수집하지 않습니다. <span
									style="padding-left: 16px;">필요한 경우 별도의 동의를 받아 수집하고 동의한
									목적을 위해서만 제한적으로 이용합니다.</span>
							</p>
							<h6 class="tabTit">수집방법</h6>
							<ul class="orderListDot">
								<li>당행 영업점에 내방한 고객으로부터 직접 수집</li>
								<li>홈페이지, 서면양식, 팩스, 전화, 상담 게시판, 이메일, 응모내역, 배송요청</li>
								<li>생성정보 수집 툴을 통한 수집</li>
								<li>고객센터의 문의사항을 통한 수집</li>
							</ul>
							<h5 class="tabTit">제8조(개인정보의 파기)</h5>
							<ol class="orderListNum">
								<li>당행은 개인정보의 보유기간이 경과된 경우에는 다음 각 호의 사유가 없는 한 보유기간의 종료일로부터
									5영업일 이내에, 개인정보의 처리 목적 달성, 해당 서비스의 폐지, 사업의 종료 등 그 개인정보가
									불필요하게 되었을 때에는 다음 각 호의 사유가 없는 한 개인정보의 처리가 불필요한 것으로 인정되는
									날로부터 5영업일 이내에 그 개인정보를 파기합니다.
									<ol class="orderListDecimal ml20">
										<li>신용정보집중기관 또는 신용조회회사가 신용정보의 집중관리·활용 또는 개인의 신용도 등을 평가하기
											위한 목적으로 개인신용정보를 보유하는 경우(보유기간에 한함)</li>
										<li>신용정보회사 등이 민·형사상의 책임 또는 시효가 지속되거나 분쟁의 입증자료로서 개인신용정보를
											보유하는 경우</li>
										<li>법령에 따라 보존하여야 하는 경우
											<table class="tblBasic" style="text-align: center;"
												summary="보존근거, 보존하는 개인정보항목에 대한 테이블">
												<caption>법령에 따라 보존하여야 하는 경우</caption>
												<colgroup>
													<col style="width: 50%;">
													<col style="width: 50%;">
												</colgroup>
												<thead>
													<tr>
														<th scope="col">보존근거</th>
														<th scope="col">보존하는 개인정보항목</th>
													</tr>
												</thead>
												<tbody>
													<tr>
														<td
															style="border-left-color: currentColor; border-left-width: 0px; border-left-style: none;">상법
															제33조</td>
														<td>계약서, 거래신청서 등 영업에 관한 중요서류(전산자료포함)</td>
													</tr>
													<tr>
														<td
															style="border-left-color: currentColor; border-left-width: 0px; border-left-style: none;">신용정보의
															이용 및 보호에 관한 법률 제20조의2</td>
														<td>금융거래 관계 설정 및 거래내역 등 금융거래정보</td>
													</tr>
													<tr>
														<td
															style="border-left-color: currentColor; border-left-width: 0px; border-left-style: none;">소득세법
															시행령 제201조의10</td>
														<td>연도별 납입액, 인출액, 납입전환 금액,과세제외금액 등 연금납입확인서
															발급을 위한 정보
														</td>
													</tr>
													<tr>
														<td
															style="border-left-color: currentColor; border-left-width: 0px; border-left-style: none;">특정금융거래의
															보고 및 이용에 관한 법률 제5조의4</td>
														<td>실지명의 확인 및 보고대상 금융거래자료송금인 및 수취인에 관한 정보 등
														</td>
													</tr>
												</tbody>
											</table>
										</li>
										<li>기타 이와 유사한 정당한 사유가 있는 경우</li>
									</ol>
								</li>
								<li>개인정보가 기록된 출력물, 서면 등은 파쇄 또는 소각의 방법으로 파기하고, 전자적 파일형태의
									개인정보는 복원이 불가능한 방법으로 영구 삭제하는 방법으로 파기합니다.</li>
							</ol>
							<h5 class="tabTit">제9조(개인정보의 안전성 확보 조치)</h5>
							<p class="contP">당행은 개인정보보호법 제29조에 따라 다음 각 호와 같이 안전성 확보에 필요한
								기술적/관리적 및 물리적 조치를 하고 있습니다.</p>
							<h6 class="tabTit">개인정보의 암호화</h6>
							<p class="contP">고객의 개인정보 중 비밀번호는 암호화 되어 저장 및 관리되고 있어, 본인만이 알
								수 있으며 중요한 데이터는 파일 및 전송 데이터를 암호화 하거나 파일 잠금 기능을 사용하는 등의 별도 보안기능을
								사용하고 있습니다.</p>
							<h6 class="tabTit">해킹 등에 대비한 기술적 대책</h6>
							<p class="contP">당행은 해킹이나 컴퓨터 바이러스 등에 의한 개인정보 유출 및 훼손을 막기 위하여
								보안프로그램을 설치하고 주기적인 갱신·점검을 하며 외부로부터 접근이 통제된 구역에 시스템을 설치하고
								기술적/물리적으로 감시 및 차단하고 있습니다.</p>
							<h6 class="tabTit">개인정보 취급 직원의 최소화 및 교육</h6>
							<p class="contP">개인정보를 취급하는 직원을 지정하고 담당자에 한정시켜 최소화 하여 개인정보를
								관리하는 대책을 시행하고 있습니다.</p>
							<h5 class="tabTit">제10조(개인정보 처리방침의 변경)</h5>
							<p class="contP">
								당행이 개인정보 처리방침을 변경하는 경우에는 변경 및 시행의 시기, 변경된 내용을 지속적으로 공개하며, 변경된
								내용은 고객이 쉽게 확인할 수있도록 변경 전·후를 비교하여 공개합니다.
							</p>
							<h5 class="tabTit">제11조(권익침해 구제방법)</h5>
							<p class="contP">고객은 개인정보침해로 인한 신고나 상담이 필요하신 경우 아래 기관에 문의하시기
								바랍니다.</p>
							<ol class="orderListDecimal ml20">
								<li>개인정보분쟁조정위원회 (<a title="새창"
									href="http://www.kopico.or.kr" target="_blank">www.kopico.or.kr</a>
									/ 1833-6972)
								</li>
								<li>한국인터넷진흥원 개인정보침해신고센터 (<a title="새창"
									href="http://privacy.kisa.or.kr" target="_blank">privacy.kisa.or.kr</a>
									/ (국번없이) 118)
								</li>
								<li>개인정보보호협회 개인정보보호인증 (<a title="새창"
									href="http://www.eprivacy.or.kr" target="_blank">www.eprivacy.or.kr</a>
									/ 02-550-9531~2)
								</li>
								<li>대검찰청 첨단범죄수사과 (<a title="새창" href="http://www.spo.go.kr"
									target="_blank">www.spo.go.kr</a> / (국번없이) 1301)
								</li>
								<li>경찰청 사이버안전지킴이 (<a title="새창"
									href="http://www.police.go.kr/www/security/cyber.jsp"
									target="_blank">www.police.go.kr/www/security/cyber.jsp</a> /
									(국번없이) 182)
								</li>
							</ol>
							<h5 class="tabTit">제12조(개인정보 보호책임자)</h5>
							<p class="contP">개인정보 보호법 제31조 제1항에 따른 당행의 개인정보 보호책임자는 다음과
								같습니다.</p>
							<ul class="orderListDot">
								<li>개인정보 보호책임자 : 정보보호본부장 상무 정의석</li>
								<li>담당부서 : 정보보호부 02-3788-5143, 5144</li>
								<li>민원처리부서 : 1588-1111 / 080-892-1111</li>
							</ul>

						</ol>

					</div>

				</div>
			</div>
		</div>
	</div>
</body>
</html>