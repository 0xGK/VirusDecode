package VirusDecode.backend.entity;

import jakarta.persistence.*;

@Entity
@Table(name="json_data")
public class JsonData {
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    private String historyName;

    private String referenceId;

    @Column(columnDefinition = "TEXT")
    private String alignment;

    @Column(columnDefinition = "TEXT")
    private String linearDesign;

    @Column(columnDefinition = "TEXT")
    private String pdb;



    public String getHistoryName() {
        return historyName;
    }

    public void setHistoryName(String historyName) {
        this.historyName = historyName;
    }

    public String getAlignment() {
        return alignment;
    }

    public void setAlignment(String alignment) {
        this.alignment = alignment;
    }

    public Long getId() {
        return id;
    }

    public void setId(Long id) {
        this.id = id;
    }

    public String getLinearDesign() {
        return linearDesign;
    }

    public void setLinearDesign(String linearDesign) {
        this.linearDesign = linearDesign;
    }

    public String getReferenceId() {
        return referenceId;
    }

    public void setReferenceId(String referenceId) {
        this.referenceId = referenceId;
    }

    public String getPdb() {
        return pdb;
    }

    public void setPdb(String pdb) {
        this.pdb = pdb;
    }
}
