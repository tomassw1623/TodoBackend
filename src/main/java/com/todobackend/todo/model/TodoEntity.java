package com.todobackend.todo.model;

import jakarta.persistence.Entity;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.Id;
import jakarta.persistence.Table;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;
import org.hibernate.annotations.GenericGenerator;

@Builder
@NoArgsConstructor
@AllArgsConstructor
@Data
@Entity                // 엔티티 임을 나타냄...
@Table(name = "Todo")  // 생성되는 테이블 명
public class TodoEntity {

    @Id  //기본키 설정 - primary key
    @GeneratedValue(generator = "system-uuid")
    @GenericGenerator(name = "system-uuid", strategy = "uuid")
    private String id;

    private String userId; // 지금은 나중에 인증처리시 사용...
    private String title;
    private boolean done;

}
