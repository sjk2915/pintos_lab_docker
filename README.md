# [WEEK12~13] Pintos VIRTUAL MEMORY

#### 커밋 컨벤션
<img width="400" height="1026" alt="image" src="https://github.com/user-attachments/assets/1a1cb7c8-41c2-4fff-ad00-9f5bdafbdb66" />   

[커밋 컨벤션 참고 자료](https://www.conventionalcommits.org/ko/v1.0.0/)

&nbsp;

#### Guide

* KAIST Guide : https://casys-kaist.github.io/pintos-kaist/
* PKU Guide : https://pkuflyingpig.gitbook.io/pintos

&nbsp;

#### 작업환경 및 설정

전체 테스트

```
    cd pintos
    source ./activate
    cd threads
    make check
    ...
    20 of 27 tests failed.
```

&nbsp;

부분 테스트

pintos 스크립트를 이용해서 alarm-multiple 테스트 프로그램을 바로 실행

```
/threads/build/ pintos -- -q run alarm-multiple
```

Pintos 테스트 프레임워크를 이용해서 자동으로 특정 테스트를 실행하고 .result 파일을 생성

```
/threads/build/ make tests/threads/priority-sema.result

```

&nbsp;

***

2. PROJECT 3 - VIRTUAL MEMORY
