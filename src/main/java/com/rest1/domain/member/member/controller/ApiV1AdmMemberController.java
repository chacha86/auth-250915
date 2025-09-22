package com.rest1.domain.member.member.controller;

import com.rest1.domain.member.member.dto.MemberWithUsernameDto;
import com.rest1.domain.member.member.entity.Member;
import com.rest1.domain.member.member.service.MemberService;
import com.rest1.global.exception.ServiceException;
import com.rest1.global.rq.Rq;
import io.swagger.v3.oas.annotations.Operation;
import lombok.RequiredArgsConstructor;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.List;

@RestController
@RequiredArgsConstructor
@RequestMapping("/api/v1/adm/members")
public class ApiV1AdmMemberController {

    private final MemberService memberService;
    private final Rq rq;

    @GetMapping
    @Transactional(readOnly = true)
    @Operation(summary = "회원 다건 조회")
    public List<MemberWithUsernameDto> getItems() {

        Member actor = rq.getActor();

        if(!actor.isAdmin()) {
            throw new ServiceException("403-1", "권한이 없습니다");
        }

        return memberService.findAll().stream()
                .map(MemberWithUsernameDto::new)
                .toList();

    }

}
