package com.ez.hana.vo;

public class CommentVO {

	int num;
	int boardNum;
	String writer;
	String content;
	String regDate;

	public int getNum() {
		return num;
	}

	public void setNum(int num) {
		this.num = num;
	}

	public int getBoardNum() {
		return boardNum;
	}

	public void setBoardNum(int boardNum) {
		this.boardNum = boardNum;
	}

	public String getWriter() {
		return writer;
	}

	public void setWriter(String writer) {
		this.writer = writer;
	}

	public String getContent() {
		return content;
	}

	public void setContent(String content) {
		this.content = content;
	}

	public String getRegDate() {
		return regDate;
	}

	public void setRegDate(String regDate) {
		this.regDate = regDate;
	}

	@Override
	public String toString() {
		return "CommentVO [num=" + num + ", boardNum=" + boardNum + ", writer=" + writer + ", content=" + content
				+ ", regDate=" + regDate + "]";
	}

}
